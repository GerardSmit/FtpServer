using System.Buffers;
using System.Net;
using System.Net.Sockets;
using FtpServer.Data;
using FtpServer.Extensions;

namespace FtpServer.Handlers;

public partial class DefaultFtpCommandHandler
{
    // ---- active mode ------------------------------------------------------

    public override ValueTask PortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.Port, out var rejected))
        {
            return rejected;
        }

        if (session.EpsvAll)
        {
            // RFC 2428 section 4: after EPSV ALL the server must refuse other data-port commands.
            return session.WriteAsync("501 Rejected: EPSV ALL is in effect.\r\n"u8, token);
        }

        if (!data.TryGetDataPort(out var endPoint))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        return SetActiveEndPointAsync(session, endPoint, token);
    }

    public override ValueTask ExtendedPortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ExtendedPort, out var rejected))
        {
            return rejected;
        }

        if (session.EpsvAll)
        {
            return session.WriteAsync("501 Rejected: EPSV ALL is in effect.\r\n"u8, token);
        }

        if (!data.TryGetExtendedPort(out var endPoint, out var networkProtocol))
        {
            // RFC 2428 section 2: 522 tells the client which protocols are on offer.
            if (networkProtocol is not (0 or 1 or 2))
            {
                return session.WriteAsync("522 Network protocol not supported, use (1,2)\r\n"u8, token);
            }

            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        return SetActiveEndPointAsync(session, endPoint!, token);
    }

    public override ValueTask LongPortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.LongPort, out var rejected))
        {
            return rejected;
        }

        if (session.EpsvAll)
        {
            return session.WriteAsync("501 Rejected: EPSV ALL is in effect.\r\n"u8, token);
        }

        if (!TryParseLongPort(data, out var endPoint))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        return SetActiveEndPointAsync(session, endPoint, token);
    }

    /// <summary>
    /// Validates and stores the endpoint a later transfer will dial out to.
    /// </summary>
    private async ValueTask SetActiveEndPointAsync(FtpSession session, IPEndPoint endPoint, CancellationToken token)
    {
        var dataOptions = options.Current.DataConnection;

        // RFC 2577 section 3: without this the server opens a connection to any host and port the
        // client names - the FTP bounce attack.
        if (!dataOptions.AllowForeignHost && !IsControlPeer(session, endPoint.Address))
        {
            await session.WriteAsync("501 Rejected: the data address must match the control connection.\r\n"u8, token);
            return;
        }

        if (endPoint.Port < dataOptions.MinimumPort)
        {
            await session.WriteAsync("501 Rejected: the data port must not be a system port.\r\n"u8, token);
            return;
        }

        // RFC 959 section 3.2: the most recent data-port command wins. A PASV left in effect would
        // keep the next transfer waiting for an inbound connection, and leak the rented port.
        await session.DataStreamProvider.ReleaseAsync();
        session.DataStreamProvider = FtpDataStreamProvider.Active;

        session.ActiveDataIp = endPoint;
        await session.WriteAsync("200 Command okay.\r\n"u8, token);
    }

    private static bool IsControlPeer(FtpSession session, IPAddress address)
    {
        if (session.RemoteEndPoint is not IPEndPoint control)
        {
            return false;
        }

        return Normalize(control.Address).Equals(Normalize(address));
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>Parses the RFC 1639 LPRT argument: af,hal,h1..hn,pal,p1..pn.</summary>
    private static bool TryParseLongPort(ReadOnlySequence<byte> data, out IPEndPoint endPoint)
    {
        endPoint = null!;

        var text = data.GetString(System.Text.Encoding.ASCII);
        var fields = text.Split(',', StringSplitOptions.TrimEntries);

        if (fields.Length < 4)
        {
            return false;
        }

        var index = 0;

        if (!TryNext(fields, ref index, out var addressFamily) ||
            !TryNext(fields, ref index, out var addressLength))
        {
            return false;
        }

        var expectedLength = addressFamily switch
        {
            4 => 4,
            6 => 16,
            _ => 0,
        };

        if (expectedLength == 0 || addressLength != expectedLength)
        {
            return false;
        }

        var addressBytes = new byte[addressLength];

        for (var i = 0; i < addressLength; i++)
        {
            if (!TryNext(fields, ref index, out var octet) || octet is < 0 or > 255)
            {
                return false;
            }

            addressBytes[i] = (byte)octet;
        }

        if (!TryNext(fields, ref index, out var portLength) || portLength is < 1 or > 2)
        {
            return false;
        }

        var port = 0;

        for (var i = 0; i < portLength; i++)
        {
            if (!TryNext(fields, ref index, out var octet) || octet is < 0 or > 255)
            {
                return false;
            }

            port = (port << 8) | octet;
        }

        if (index != fields.Length || port is < 1 or > 65535)
        {
            return false;
        }

        endPoint = new IPEndPoint(new IPAddress(addressBytes), port);
        return true;

        static bool TryNext(string[] fields, ref int index, out int value)
        {
            value = 0;
            return index < fields.Length && int.TryParse(fields[index++], out value);
        }
    }

    // ---- passive mode -----------------------------------------------------

    public override ValueTask PassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.PassiveMode, out var rejected))
        {
            return rejected;
        }

        if (session.EpsvAll)
        {
            return session.WriteAsync("501 Rejected: EPSV ALL is in effect.\r\n"u8, token);
        }

        return StartPassiveModeAsync(session, PassiveReplyKind.HostPort, token);
    }

    public override ValueTask ExtendedPassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ExtendedPassiveMode, out var rejected))
        {
            return rejected;
        }

        if (!data.IsEmpty)
        {
            if (data.EqualsIgnoreCase("ALL"u8))
            {
                // RFC 2428 section 4: latch the session into extended passive mode only.
                session.EpsvAll = true;
                return session.WriteAsync("200 EPSV ALL command successful.\r\n"u8, token);
            }

            if (!data.TryGetInt32(out var networkProtocol))
            {
                return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
            }

            if (networkProtocol is not (1 or 2))
            {
                return session.WriteAsync("522 Network protocol not supported, use (1,2)\r\n"u8, token);
            }
        }

        return StartPassiveModeAsync(session, PassiveReplyKind.Extended, token);
    }

    public override ValueTask LongPassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.LongPassiveMode, out var rejected))
        {
            return rejected;
        }

        if (session.EpsvAll)
        {
            return session.WriteAsync("501 Rejected: EPSV ALL is in effect.\r\n"u8, token);
        }

        return StartPassiveModeAsync(session, PassiveReplyKind.Long, token);
    }

    private enum PassiveReplyKind
    {
        HostPort,
        Extended,
        Long,
    }

    private async ValueTask StartPassiveModeAsync(FtpSession session, PassiveReplyKind kind, CancellationToken token)
    {
        if (!options.Current.Passive)
        {
            await session.WriteAsync("502 Command not implemented.\r\n"u8, token);
            return;
        }

        var peer = (session.RemoteEndPoint as IPEndPoint)?.Address;
        var local = (session.LocalEndPoint as IPEndPoint)?.Address;

        if (local is null)
        {
            await session.WriteAsync("425 Can't open data connection.\r\n"u8, token);
            return;
        }

        // Release a port rented by an earlier PASV that no transfer ever claimed.
        await session.DataStreamProvider.ReleaseAsync();
        session.DataStreamProvider = FtpDataStreamProvider.Active;

        var owner = await passivePortProvider.TryRentAsync(peer is null ? null : Normalize(peer));

        if (owner is null)
        {
            await session.WriteAsync("425 Can't open data connection: no free port.\r\n"u8, token);
            return;
        }

        // The listener is armed; the accept itself is deferred until a transfer command runs, so
        // this command produces exactly one reply.
        session.DataStreamProvider = new FtpDataStreamProviderPassive(owner, session.RemoteEndPoint);

        // The client has this long, from the reply on, to connect and start a transfer; after that
        // the port is free for somebody else.
        owner.ExpireAfter(options.Current.DataConnection.Timeout);

        switch (kind)
        {
            case PassiveReplyKind.Extended:
                // RFC 2428 section 3 specifies 229, not the 227 used by PASV.
                await session.WriteExtendedPassiveModeAsync("229 Entering Extended Passive Mode ("u8, owner.Port, ")\r\n"u8, token);
                return;

            case PassiveReplyKind.Long:
                await WriteLongPassiveAsync(session, SelectAdvertisedAddress(local, peer), owner.Port, token);
                return;

            default:
                {
                    var advertised = ToIPv4(SelectAdvertisedAddress(local, peer));

                    if (advertised is null)
                    {
                        // PASV cannot express an IPv6 address; the client must use EPSV.
                        await session.DataStreamProvider.ReleaseAsync();
                        session.DataStreamProvider = FtpDataStreamProvider.Active;
                        await session.WriteAsync("522 Network protocol not supported, use (1,2)\r\n"u8, token);
                        return;
                    }

                    // RFC 959 section 4.1.2 requires the tuple to be parenthesised.
                    await session.WritePassiveModeAsync(
                        "227 Entering Passive Mode ("u8,
                        advertised,
                        owner.Port >> 8,
                        owner.Port & 0xFF,
                        ").\r\n"u8,
                        token);
                    return;
                }
        }
    }

    private static ValueTask WriteLongPassiveAsync(FtpSession session, IPAddress advertised, int port, CancellationToken token)
    {
        var bytes = advertised.GetAddressBytes();
        var family = advertised.AddressFamily == AddressFamily.InterNetworkV6 ? 6 : 4;

        var text = $"228 Entering Long Passive Mode ({family},{bytes.Length},{string.Join(',', bytes)},2,{port >> 8},{port & 0xFF})\r\n";
        return session.WriteAsync(text, token);
    }

    private static IPAddress? ToIPv4(IPAddress address)
    {
        var normalized = Normalize(address);
        return normalized.AddressFamily == AddressFamily.InterNetwork ? normalized : null;
    }

    /// <summary>
    /// Picks the address a PASV/LPSV reply advertises. The dual-stack listener reports an IPv4
    /// endpoint as ::ffff:a.b.c.d, which an IPv4 client cannot use, so it is normalised first.
    /// </summary>
    private IPAddress SelectAdvertisedAddress(IPAddress local, IPAddress? peer)
        => SelectAdvertisedAddress(local, peer, options.Current.DataConnection.PublicAddress);

    /// <summary>
    /// A configured public address replaces the local one for every peer but a loopback one. A LAN
    /// peer gets it too: behind Docker or another port forward the local address is the
    /// container's, which no client can reach, and the peer a forward reports can be the
    /// forwarder's own private address, so a private peer says nothing about which address works.
    /// A client that took the reply literally (Beyond Compare does) then timed out on its data
    /// connection, where clients that substitute the control address (FileZilla) did not notice.
    /// </summary>
    internal static IPAddress SelectAdvertisedAddress(IPAddress local, IPAddress? peer, string? configured)
    {
        var normalized = Normalize(local);

        if (configured is not { Length: > 0 } || !IPAddress.TryParse(configured, out var publicAddress))
        {
            return normalized;
        }

        publicAddress = Normalize(publicAddress);

        // The substituted address must be of the family the reply format carries.
        if (publicAddress.AddressFamily != normalized.AddressFamily)
        {
            return normalized;
        }

        // A client on the server itself reaches the local address, and may not reach the public one.
        if (peer is not null && IPAddress.IsLoopback(Normalize(peer)))
        {
            return normalized;
        }

        return publicAddress;
    }

    public override ValueTask SinglePortPassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        // SPSV never left draft status and no mainstream client sends it.
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);
}
