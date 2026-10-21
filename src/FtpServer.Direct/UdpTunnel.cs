using System.Net;
using System.Net.Sockets;
using LiteNetLib;

namespace FtpServer.Direct;

public sealed class UdpTunnelOptions
{
    public static readonly IReadOnlyList<string> DefaultStunServers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

    /// <summary>
    /// Ask STUN servers for the public address, so a machine outside this network can be told where to
    /// send. Off offers this machine's own addresses only, for a tunnel within a network.
    /// </summary>
    public bool UseStun { get; init; } = true;

    public IReadOnlyList<string> StunServers { get; init; } = DefaultStunServers;

    public TimeSpan StunTimeout { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Offer 127.0.0.1 as well; for tests on one machine.</summary>
    public bool IncludeLoopback { get; init; }
}

/// <summary>How the NAT in front of this machine maps its UDP port, as the STUN servers saw it.</summary>
public enum NatMapping
{
    /// <summary>No STUN server answered, or none was asked.</summary>
    Unknown,

    /// <summary>The public address is this machine's own: there is no NAT.</summary>
    None,

    /// <summary>Every STUN server saw the same public port: a hole punched toward the other side opens.</summary>
    Consistent,

    /// <summary>Each STUN server saw another public port (symmetric NAT): punching will most likely fail.</summary>
    Varies
}

/// <summary>
/// One side of a UDP tunnel: a socket on a port of its own, the addresses it may be reached at, and the
/// punching that opens the NATs and firewalls of both sides toward each other. Each side is told the
/// other's <see cref="Candidates"/> by whoever brings them together, and both start at about the same
/// time: one accepts, the other connects. The result is a reliable stream; it carries no security of its
/// own, so whatever runs over it brings that (TLS with pinned certificates).
/// </summary>
public sealed class UdpTunnel : IDisposable
{
    private static readonly byte[] Punch = "punch"u8.ToArray();

    private readonly NetManager _manager;
    private readonly EventBasedNetListener _events;
    private readonly UdpStream _stream;
    private readonly Lock _gate = new();
    private readonly List<ConnectionRequest> _early = [];
    private string? _key;
    private bool _connecting;
    private int _used;

    private UdpTunnel(NetManager manager, EventBasedNetListener events, UdpStream stream, List<IPEndPoint> candidates, IReadOnlyList<IPEndPoint> mapped, NatMapping nat)
    {
        _manager = manager;
        _events = events;
        _stream = stream;
        Candidates = candidates;
        Mapped = mapped;
        Nat = nat;

        // Requests are taken from the moment the port is open: LiteNetLib raises a request once and only updates
        // it on later attempts, so one that came in before AcceptAsync would otherwise never be answered.
        _events.ConnectionRequestEvent += OnConnectionRequest;
    }

    public int Port => _manager.LocalPort;

    /// <summary>Where the other side should send: this machine's own addresses, then the public one the STUN servers saw.</summary>
    public IReadOnlyList<IPEndPoint> Candidates { get; }

    /// <summary>The public addresses the STUN servers saw, one per server that answered.</summary>
    public IReadOnlyList<IPEndPoint> Mapped { get; }

    public NatMapping Nat { get; }

    public static async Task<UdpTunnel> OpenAsync(UdpTunnelOptions options, CancellationToken token)
    {
        for (var attempt = 0; ; attempt++)
        {
            int port;
            IReadOnlyList<IPEndPoint> mapped = [];

            // The port is taken and asked about with a plain socket first, as the tunnel cannot send a STUN
            // request itself, and then handed over: the NAT keeps its mapping for the port meanwhile.
            using (var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                probe.Bind(new IPEndPoint(IPAddress.Any, 0));
                port = ((IPEndPoint)probe.LocalEndPoint!).Port;

                if (options.UseStun)
                {
                    mapped = await StunClient.QueryAsync(probe, options.StunServers, options.StunTimeout, token);
                }
            }

            var events = new EventBasedNetListener();
            var manager = new NetManager(events)
            {
                ChannelsCount = UdpStream.Channels,
                UnconnectedMessagesEnabled = true,
                UnsyncedEvents = true,
                UnsyncedReceiveEvent = true,
                UnsyncedDeliveryEvent = true,
                IPv6Enabled = true,
                AutoRecycle = true,
                MtuDiscovery = true,
                UpdateTime = 1,
                DisconnectTimeout = 10_000,
                ReconnectDelay = 200
            };

            if (!manager.Start(IPAddress.Any, IPAddress.IPv6Any, port))
            {
                manager.Stop();

                if (attempt == 2)
                {
                    throw new IOException("No UDP port could be opened.");
                }

                continue;
            }

            var local = Direct.Candidates.LocalAddresses().Select(x => new IPEndPoint(x, port)).ToList();

            if (options.IncludeLoopback)
            {
                local.Insert(0, new IPEndPoint(IPAddress.Loopback, port));
            }

            var candidates = local.Concat(mapped).Distinct().ToList();

            var nat = mapped.Count == 0 ? NatMapping.Unknown
                : mapped.Any(x => local.Contains(x)) ? NatMapping.None
                : mapped.Select(x => x.Port).Distinct().Count() == 1 ? NatMapping.Consistent
                : NatMapping.Varies;

            return new UdpTunnel(manager, events, new UdpStream(manager, events), candidates, mapped, nat);
        }
    }

    /// <summary>
    /// Waits for the other side to connect with <paramref name="key"/>, sending to its
    /// <paramref name="peer"/> candidates meanwhile so the holes on this side open. The stream owns the
    /// tunnel: disposing it closes both.
    /// </summary>
    public async Task<Stream> AcceptAsync(IReadOnlyList<IPEndPoint> peer, string key, TimeSpan timeout, CancellationToken token)
    {
        Use();

        foreach (var request in TakeEarly(key, connecting: false))
        {
            Answer(request);
        }

        // The first connection that says hello is the one; the other side drops any other that got through.
        await PunchUntilAsync(peer, _stream.Bound, timeout, token);
        return _stream;
    }

    /// <summary>Connects to the other side, which accepts with the same <paramref name="key"/>, at whichever candidate answers first.</summary>
    public async Task<Stream> ConnectAsync(IReadOnlyList<IPEndPoint> peer, string key, TimeSpan timeout, CancellationToken token)
    {
        Use();

        _manager.MaxConnectAttempts = Math.Max(1, (int)(timeout.TotalMilliseconds / _manager.ReconnectDelay));

        foreach (var request in TakeEarly(null, connecting: true))
        {
            request.Reject();
        }

        var first = new TaskCompletionSource<NetPeer>(TaskCreationOptions.RunContinuationsAsynchronously);

        _events.PeerConnectedEvent += connected =>
        {
            if (first.TrySetResult(connected))
            {
                _stream.Bind(connected);
                _stream.SendHello();

                foreach (var other in _manager.ConnectedPeerList().Where(x => x != connected))
                {
                    _manager.DisconnectPeer(other);
                }
            }
            else
            {
                _manager.DisconnectPeer(connected);
            }
        };

        foreach (var endpoint in peer)
        {
            _manager.Connect(endpoint, key);
        }

        await PunchUntilAsync(peer, first.Task, timeout, token);
        return _stream;
    }

    private void OnConnectionRequest(ConnectionRequest request)
    {
        lock (_gate)
        {
            if (_key is null && !_connecting)
            {
                if (_early.Count < Direct.Candidates.Max)
                {
                    _early.Add(request);
                }
                else
                {
                    request.Reject();
                }

                return;
            }
        }

        Answer(request);
    }

    private void Answer(ConnectionRequest request)
    {
        if (_key is null || _stream.IsBound)
        {
            request.Reject();
        }
        else
        {
            request.AcceptIfKey(_key);
        }
    }

    private List<ConnectionRequest> TakeEarly(string? key, bool connecting)
    {
        lock (_gate)
        {
            _key = key;
            _connecting = connecting;

            var early = _early.ToList();
            _early.Clear();
            return early;
        }
    }

    private void Use()
    {
        if (Interlocked.Exchange(ref _used, 1) == 1)
        {
            throw new InvalidOperationException("A tunnel accepts or connects once.");
        }
    }

    private async Task PunchUntilAsync(IReadOnlyList<IPEndPoint> peer, Task done, TimeSpan timeout, CancellationToken token)
    {
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(token);
        waiting.CancelAfter(timeout);

        try
        {
            while (!done.IsCompleted)
            {
                waiting.Token.ThrowIfCancellationRequested();

                foreach (var endpoint in peer)
                {
                    _manager.SendUnconnectedMessage(Punch, endpoint);
                }

                _manager.TriggerUpdate();
                await Task.WhenAny(done, Task.Delay(100, waiting.Token));
            }

            await done;
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            Dispose();
            throw new IOException("The other side could not be reached over UDP.");
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public void Dispose() => _stream.Dispose();
}

internal static class NetManagerExtensions
{
    public static List<NetPeer> ConnectedPeerList(this NetManager manager)
    {
        var peers = new List<NetPeer>();
        manager.GetConnectedPeers(peers);
        return peers;
    }
}
