using System.Net;
using System.Net.Sockets;

namespace FtpServer.Relay;

/// <summary>Where the client's next data connection comes from: a passive port it connects to, or its own port (PORT/EPRT).</summary>
internal abstract class ClientData : IDisposable
{
    /// <summary>How long a client gets to open or accept the data connection.</summary>
    protected static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    public abstract Task<TcpClient> OpenAsync(CancellationToken token);

    public virtual void Dispose()
    {
    }

    internal static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}

/// <summary>A port of the passive range the client connects to; only the client itself may.</summary>
internal sealed class PassiveData(TcpListener listener, IPAddress client, PassivePorts ports) : ClientData
{
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

    public override async Task<TcpClient> OpenAsync(CancellationToken token)
    {
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(token);
        waiting.CancelAfter(ConnectTimeout);

        while (true)
        {
            var accepted = await listener.AcceptTcpClientAsync(waiting.Token);

            // Someone else taking the transfer would read or write the client's files.
            if (Normalize(((IPEndPoint)accepted.Client.RemoteEndPoint!).Address).Equals(client))
            {
                accepted.NoDelay = true;
                return accepted;
            }

            accepted.Dispose();
        }
    }

    public override void Dispose() => ports.Release(listener);
}

/// <summary>The client's own port (PORT/EPRT), connected to when the transfer starts.</summary>
internal sealed class ActiveData(IPEndPoint target) : ClientData
{
    public override async Task<TcpClient> OpenAsync(CancellationToken token)
    {
        var data = new TcpClient(target.AddressFamily) { NoDelay = true };

        try
        {
            using var connecting = CancellationTokenSource.CreateLinkedTokenSource(token);
            connecting.CancelAfter(ConnectTimeout);
            await data.ConnectAsync(target, connecting.Token);
            return data;
        }
        catch
        {
            data.Dispose();
            throw;
        }
    }
}

/// <summary>The passive range, shared by every session.</summary>
internal sealed class PassivePorts
{
    private readonly IPAddress _address;
    private readonly int _start;
    private readonly int _end;
    private readonly Lock _gate = new();
    private readonly HashSet<int> _taken = [];
    private int _next;

    public PassivePorts(IPAddress address, int start, int end)
    {
        _address = address;
        _start = start;
        _end = end;
        _next = start;
    }

    /// <summary>A listener on a free port of the range, or null when every port is taken.</summary>
    public TcpListener? Rent()
    {
        lock (_gate)
        {
            for (var tried = 0; tried <= _end - _start; tried++)
            {
                var port = _next;
                _next = _next >= _end ? _start : _next + 1;

                if (_taken.Contains(port))
                {
                    continue;
                }

                var listener = new TcpListener(_address, port);

                if (_address.Equals(IPAddress.IPv6Any))
                {
                    listener.Server.DualMode = true;
                }

                try
                {
                    listener.Start(1);
                }
                catch (SocketException)
                {
                    // In use by another program, or reserved by the system.
                    continue;
                }

                _taken.Add(port);
                return listener;
            }

            return null;
        }
    }

    public void Release(TcpListener listener)
    {
        lock (_gate)
        {
            _taken.Remove(((IPEndPoint)listener.LocalEndpoint).Port);
        }

        listener.Stop();
    }
}
