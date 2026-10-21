using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace FtpServer.Direct;

/// <summary>
/// Asks STUN servers (RFC 5389 binding requests) which public address and port a UDP socket is seen from,
/// which is what the other side has to send to for a hole to open.
/// </summary>
public static class StunClient
{
    private const ushort BindingRequest = 0x0001;
    private const ushort BindingSuccess = 0x0101;
    private const ushort MappedAddress = 0x0001;
    private const ushort XorMappedAddress = 0x0020;
    private const uint MagicCookie = 0x2112A442;

    /// <summary>
    /// The address <paramref name="socket"/> is seen from by each server that answered within
    /// <paramref name="timeout"/>; a server that did not answer or cannot be resolved is left out.
    /// </summary>
    public static async Task<IReadOnlyList<IPEndPoint>> QueryAsync(Socket socket, IEnumerable<string> servers, TimeSpan timeout, CancellationToken token)
    {
        var requests = new Dictionary<string, (IPEndPoint Server, byte[] Transaction)>();

        foreach (var server in servers)
        {
            if (await ResolveAsync(server, socket.AddressFamily, token) is not { } endpoint)
            {
                continue;
            }

            var transaction = RandomNumberGenerator.GetBytes(12);
            requests[Convert.ToHexString(transaction)] = (endpoint, transaction);
        }

        var mapped = new List<IPEndPoint>();

        if (requests.Count == 0)
        {
            return mapped;
        }

        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(token);
        waiting.CancelAfter(timeout);

        var buffer = new byte[1024];
        var remaining = new System.Collections.Concurrent.ConcurrentDictionary<string, bool>(requests.Keys.Select(x => KeyValuePair.Create(x, true)));

        // Sent again every 250 ms while unanswered: UDP may lose a request.
        using var resend = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        var sender = Task.Run(async () =>
        {
            do
            {
                foreach (var key in remaining.Keys)
                {
                    var (server, transaction) = requests[key];

                    try
                    {
                        await socket.SendToAsync(Request(transaction), SocketFlags.None, server, waiting.Token);
                    }
                    catch (SocketException)
                    {
                        // An unreachable server answers nothing; the others still may.
                    }
                }
            }
            while (await resend.WaitForNextTickAsync(waiting.Token));
        }, waiting.Token);

        try
        {
            while (!remaining.IsEmpty)
            {
                SocketReceiveFromResult received;

                try
                {
                    received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0), waiting.Token);
                }
                catch (SocketException)
                {
                    // An ICMP "port unreachable" from one server surfaces here on Windows.
                    continue;
                }

                if (Parse(buffer.AsSpan(0, received.ReceivedBytes)) is { } answer && remaining.TryRemove(answer.Transaction, out _))
                {
                    mapped.Add(answer.Mapped);
                }
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            // Timed out: what answered is the result.
        }
        finally
        {
            await waiting.CancelAsync();

            try
            {
                await sender;
            }
            catch (OperationCanceledException)
            {
            }
        }

        return mapped;
    }

    private static async Task<IPEndPoint?> ResolveAsync(string server, AddressFamily family, CancellationToken token)
    {
        if (!Candidates.TryParseHostPort(server, 3478, out var host, out var port))
        {
            return null;
        }

        if (IPAddress.TryParse(host, out var literal))
        {
            return literal.AddressFamily == family ? new IPEndPoint(literal, port) : null;
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, family, token);
            return addresses.Length == 0 ? null : new IPEndPoint(addresses[0], port);
        }
        catch (SocketException)
        {
            return null;
        }
    }

    internal static byte[] Request(byte[] transaction)
    {
        var request = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(request, BindingRequest);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 0);
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4), MagicCookie);
        transaction.CopyTo(request, 8);
        return request;
    }

    /// <summary>The transaction (in hex) and mapped address of a binding success response; null for anything else.</summary>
    internal static (string Transaction, IPEndPoint Mapped)? Parse(ReadOnlySpan<byte> message)
    {
        if (message.Length < 20 ||
            BinaryPrimitives.ReadUInt16BigEndian(message) != BindingSuccess ||
            BinaryPrimitives.ReadUInt32BigEndian(message[4..]) != MagicCookie)
        {
            return null;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        var transaction = message.Slice(8, 12);

        if (message.Length < 20 + length)
        {
            return null;
        }

        var attributes = message.Slice(20, length);
        IPEndPoint? plain = null;

        while (attributes.Length >= 4)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(attributes);
            var size = BinaryPrimitives.ReadUInt16BigEndian(attributes[2..]);

            if (attributes.Length < 4 + size)
            {
                break;
            }

            var value = attributes.Slice(4, size);

            if (type == XorMappedAddress && ReadAddress(value, transaction, xor: true) is { } xored)
            {
                return (Convert.ToHexString(transaction), xored);
            }

            if (type == MappedAddress)
            {
                plain = ReadAddress(value, transaction, xor: false);
            }

            // Attributes are padded to a multiple of four bytes.
            var next = 4 + ((size + 3) & ~3);
            attributes = attributes.Length >= next ? attributes[next..] : [];
        }

        return plain is null ? null : (Convert.ToHexString(transaction), plain);
    }

    private static IPEndPoint? ReadAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> transaction, bool xor)
    {
        if (value.Length < 8)
        {
            return null;
        }

        var family = value[1];
        var port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
        Span<byte> cookie = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(cookie, MagicCookie);

        if (xor)
        {
            port ^= (ushort)(MagicCookie >> 16);
        }

        switch (family)
        {
            case 0x01:
            {
                var address = value.Slice(4, 4).ToArray();

                if (xor)
                {
                    for (var i = 0; i < 4; i++)
                    {
                        address[i] ^= cookie[i];
                    }
                }

                return new IPEndPoint(new IPAddress(address), port);
            }
            case 0x02 when value.Length >= 20:
            {
                var address = value.Slice(4, 16).ToArray();

                if (xor)
                {
                    for (var i = 0; i < 16; i++)
                    {
                        address[i] ^= i < 4 ? cookie[i] : transaction[i - 4];
                    }
                }

                return new IPEndPoint(new IPAddress(address), port);
            }
            default:
                return null;
        }
    }
}
