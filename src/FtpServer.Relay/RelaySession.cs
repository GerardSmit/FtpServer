using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace FtpServer.Relay;

/// <summary>
/// One client: its commands go to its own connection to the FTPS server and the replies come back as
/// they are. Only what a plain client and a TLS server see differently is handled here: TLS commands,
/// HOST, the data connections, and the features and listings described in <see cref="Rewrites"/>.
/// </summary>
internal sealed class RelaySession(TcpClient client, RelayOptions options, PassivePorts ports, ILogger logger)
{
    private static readonly HashSet<string> Transfers = new(StringComparer.Ordinal) { "LIST", "NLST", "MLSD", "RETR", "STOR", "STOU", "APPE" };
    private static readonly HashSet<string> Uploads = new(StringComparer.Ordinal) { "STOR", "STOU", "APPE" };

    private readonly TimeZoneInfo _serverZone = Rewrites.Zone(options.Upstream.ListTimeZone);
    private readonly TimeZoneInfo _clientZone = Rewrites.Zone(options.ListTimeZone);
    private readonly Channel<byte[]> _commands = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly Queue<byte[]> _deferred = new();

    private LineChannel _client = null!;
    private Upstream _upstream = null!;
    private IPAddress _clientAddress = IPAddress.None;
    private ClientData? _data;
    private string? _user;

    public async Task RunAsync(CancellationToken token)
    {
        using var _ = client;
        var remote = (IPEndPoint)client.Client.RemoteEndPoint!;
        _clientAddress = ClientData.Normalize(remote.Address);
        _client = new LineChannel(client.GetStream());

        try
        {
            _upstream = await Upstream.ConnectAsync(options.Upstream, token);
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException ||
                                   (ex is OperationCanceledException && !token.IsCancellationRequested))
        {
            logger.LogError(ex, "Connecting to {Host}:{Port} for {Client} failed", options.Upstream.Host, options.Upstream.Port, remote);
            await TryReplyAsync("421 The FTPS server cannot be reached.", token);
            return;
        }

        await using var upstream = _upstream;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var reading = ReadCommandsAsync(stop.Token);

        try
        {
            await _client.WriteReplyAsync(_upstream.Greeting, token);

            while (await NextCommandAsync(token) is { } line)
            {
                if (!await HandleAsync(line, token))
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException ||
                                   (ex is OperationCanceledException && !token.IsCancellationRequested))
        {
            logger.LogWarning("Relaying for {User} from {Client} ended: {Error}", _user, remote, ex.Message);
        }
        finally
        {
            _data?.Dispose();
            await stop.CancelAsync();
            await reading;
        }
    }

    /// <summary>Reads the client's commands as they come, so an ABOR is seen while a transfer runs.</summary>
    private async Task ReadCommandsAsync(CancellationToken token)
    {
        try
        {
            while (await _client.ReadLineAsync(token) is { } line)
            {
                await _commands.Writer.WriteAsync(line, token);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
        }
        finally
        {
            _commands.Writer.TryComplete();
        }
    }

    private async Task<byte[]?> NextCommandAsync(CancellationToken token)
    {
        if (_deferred.TryDequeue(out var deferred))
        {
            return deferred;
        }

        return await _commands.Reader.WaitToReadAsync(token) && _commands.Reader.TryRead(out var line) ? line : null;
    }

    /// <summary>The verb, upper-cased, and its argument; Telnet IP and Synch before an ABOR are dropped.</summary>
    private static (string Verb, string Argument) Parse(byte[] line)
    {
        var start = 0;

        while (start < line.Length && (line[start] < 0x20 || line[start] >= 0x7F))
        {
            start++;
        }

        var text = Encoding.UTF8.GetString(line, start, line.Length - start);
        var space = text.IndexOf(' ');

        return space < 0
            ? (text.ToUpperInvariant(), "")
            : (text[..space].ToUpperInvariant(), text[(space + 1)..]);
    }

    /// <summary>False when the session is over.</summary>
    private async Task<bool> HandleAsync(byte[] line, CancellationToken token)
    {
        var (verb, argument) = Parse(line);

        switch (verb)
        {
            // The client side is plain by design; the server side is always TLS.
            case "AUTH" or "CCC" or "ADAT":
                await ReplyAsync("502 Command not implemented.", token);
                return true;

            case "PBSZ":
                await ReplyAsync("200 PBSZ=0", token);
                return true;

            case "PROT":
                await ReplyAsync(argument.Trim().Equals("C", StringComparison.OrdinalIgnoreCase)
                    ? "200 Protection level set to C."
                    : "536 Only clear data connections are offered.", token);
                return true;

            // The relay knows which server it relays to.
            case "HOST":
                await ReplyAsync("220 Host accepted.", token);
                return true;

            case "PASV":
                await PassiveAsync(extended: false, token);
                return true;

            case "EPSV":
                if (argument.Trim().Equals("ALL", StringComparison.OrdinalIgnoreCase))
                {
                    await ReplyAsync("200 EPSV ALL accepted.", token);
                }
                else
                {
                    await PassiveAsync(extended: true, token);
                }

                return true;

            case "PORT" or "EPRT":
                await ActiveAsync(verb, argument, token);
                return true;

            case "MLSD" or "MLST" when !options.OfferMlsd:
                await ReplyAsync("502 Command not implemented.", token);
                return true;

            case "FEAT":
                return await ForwardAsync(line, token, reply => Rewrites.Features(reply, options.OfferMlsd));

            case "USER":
                _user = argument.Trim();
                return await ForwardAsync(line, token);

            case "PASS":
                return await ForwardAsync(line, token, reply =>
                {
                    if (reply.Code == "230")
                    {
                        logger.LogInformation("{User} from {Client} logged in at {Host}", _user, _clientAddress, options.Upstream.Host);
                    }
                    else if (reply.Code == "530")
                    {
                        logger.LogWarning("{User} from {Client} was refused by {Host}", _user, _clientAddress, options.Upstream.Host);
                    }

                    return reply;
                });

            case "QUIT":
                await ForwardAsync(line, token);
                return false;

            default:
                return Transfers.Contains(verb)
                    ? await TransferAsync(verb, argument, line, token)
                    : await ForwardAsync(line, token);
        }
    }

    private Task ReplyAsync(string line, CancellationToken token) => _client.WriteLineAsync(line, token);

    private async Task TryReplyAsync(string line, CancellationToken token)
    {
        try
        {
            await ReplyAsync(line, token);
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
        }
    }

    /// <summary>Passes a command on and its reply back; false when the server is gone.</summary>
    private async Task<bool> ForwardAsync(byte[] line, CancellationToken token, Func<FtpReply, FtpReply>? change = null)
    {
        if (!await DrainUnsolicitedAsync(token))
        {
            return false;
        }

        await _upstream.SendAsync(line, token);

        if (await _upstream.ReplyAsync(token) is not { } reply)
        {
            await LostAsync(token);
            return false;
        }

        await _client.WriteReplyAsync(change?.Invoke(reply) ?? reply, token);
        return reply.Code != "421";
    }

    /// <summary>The server closed the connection or did not answer in time: said in the log, and to the client.</summary>
    private async Task LostAsync(CancellationToken token)
    {
        logger.LogWarning("The connection to {Host} of {User} from {Client} was lost or did not answer in time", options.Upstream.Host, _user, _clientAddress);
        await ReplyAsync("421 The connection to the FTPS server was lost.", token);
    }

    /// <summary>
    /// A reply nobody asked for (the server's 421 before it closes an idle connection) is passed on
    /// before the next command, so it is not taken for that command's reply. False when it ends the session.
    /// </summary>
    private async Task<bool> DrainUnsolicitedAsync(CancellationToken token)
    {
        while (_upstream.HasUnsolicited)
        {
            var stale = await _upstream.ReplyAsync(token, TimeSpan.FromSeconds(2));

            if (stale is null)
            {
                await LostAsync(token);
                return false;
            }

            if (stale.Code == "421")
            {
                logger.LogInformation("{Host} closed the connection of {User} from {Client}: {Reply}", options.Upstream.Host, _user, _clientAddress, stale.Text);
                await ReplyAsync(Encoding.UTF8.GetString(stale.Lines[^1]), token);
                return false;
            }
        }

        return true;
    }

    private async Task PassiveAsync(bool extended, CancellationToken token)
    {
        _data?.Dispose();
        _data = null;

        if (ports.Rent() is not { } listener)
        {
            await ReplyAsync("425 No passive port is free.", token);
            return;
        }

        var data = new PassiveData(listener, _clientAddress, ports);

        if (extended)
        {
            _data = data;
            await ReplyAsync($"229 Entering Extended Passive Mode (|||{data.Port}|)", token);
            return;
        }

        // The address the client reached this relay on, which is one it can reach again.
        var local = ClientData.Normalize(((IPEndPoint)client.Client.LocalEndPoint!).Address);

        if (local.AddressFamily != AddressFamily.InterNetwork)
        {
            data.Dispose();
            await ReplyAsync("425 PASV is for IPv4; use EPSV.", token);
            return;
        }

        _data = data;
        var bytes = local.GetAddressBytes();
        await ReplyAsync($"227 Entering Passive Mode ({bytes[0]},{bytes[1]},{bytes[2]},{bytes[3]},{data.Port >> 8},{data.Port & 0xFF}).", token);
    }

    /// <summary>PORT h1,h2,h3,h4,p1,p2 or EPRT |1|address|port|; only to the client's own address.</summary>
    private async Task ActiveAsync(string verb, string argument, CancellationToken token)
    {
        _data?.Dispose();
        _data = null;

        IPEndPoint? target = null;

        if (verb == "PORT" && argument.Trim().Split(',') is [var h1, var h2, var h3, var h4, var p1, var p2] &&
            IPAddress.TryParse($"{h1}.{h2}.{h3}.{h4}", out var address) &&
            int.TryParse(p1, NumberStyles.None, CultureInfo.InvariantCulture, out var high) &&
            int.TryParse(p2, NumberStyles.None, CultureInfo.InvariantCulture, out var low) && high < 256 && low < 256)
        {
            target = new IPEndPoint(address, (high << 8) | low);
        }
        else if (verb == "EPRT" && argument.Trim() is { Length: > 3 } text &&
                 text[1..^1].Split(text[0]) is [_, var host, var portText] &&
                 IPAddress.TryParse(host, out var extendedAddress) &&
                 int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is > 0 and < 65536)
        {
            target = new IPEndPoint(extendedAddress, port);
        }

        if (target is null)
        {
            await ReplyAsync("501 Syntax error in parameters or arguments.", token);
            return;
        }

        // A data connection to anyone but the client would let the relay be used to reach other hosts.
        if (!ClientData.Normalize(target.Address).Equals(_clientAddress) || target.Port < 1024)
        {
            await ReplyAsync("500 Illegal PORT command.", token);
            return;
        }

        _data = new ActiveData(target);
        await ReplyAsync("200 Command okay.", token);
    }

    /// <summary>
    /// A transfer: a data connection to the server (protected) and one to the client (plain), with
    /// the bytes copied between them, and the server's replies passed on. False when the session is over.
    /// </summary>
    private async Task<bool> TransferAsync(string verb, string argument, byte[] line, CancellationToken token)
    {
        if (_data is not { } clientData)
        {
            await ReplyAsync("425 Use PASV or PORT first.", token);
            return true;
        }

        // A passive port is for one transfer, as on any server.
        _data = null;

        using (clientData)
        {
            if (!await DrainUnsolicitedAsync(token))
            {
                return false;
            }

            TcpClient upstreamData;

            try
            {
                upstreamData = await _upstream.OpenDataAsync(token);
            }
            catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !token.IsCancellationRequested))
            {
                logger.LogWarning(ex, "Opening a data connection to {Host} failed", options.Upstream.Host);
                await ReplyAsync("425 Cannot open a data connection to the FTPS server.", token);
                return true;
            }

            using (upstreamData)
            {
                // LIST gets -T, so its times have seconds and a year, and can be converted exactly.
                if (verb == "LIST")
                {
                    await _upstream.SendAsync(Rewrites.ListWithCompleteTimes(argument), token);
                }
                else
                {
                    await _upstream.SendAsync(line, token);
                }

                if (await _upstream.ReplyAsync(token) is not { } start)
                {
                    await LostAsync(token);
                    return false;
                }

                if (!start.IsPreliminary)
                {
                    await _client.WriteReplyAsync(start, token);
                    return start.Code != "421";
                }

                SslStream serverData;

                try
                {
                    serverData = await _upstream.ProtectAsync(upstreamData, token);
                }
                catch (Exception ex) when (ex is IOException or AuthenticationException || (ex is OperationCanceledException && !token.IsCancellationRequested))
                {
                    logger.LogWarning(ex, "Protecting a data connection to {Host} failed", options.Upstream.Host);
                    upstreamData.Dispose();
                    return await FailTransferAsync("425 Cannot open a data connection to the FTPS server.", token);
                }

                await using (serverData)
                {
                    await _client.WriteReplyAsync(start, token);

                    TcpClient clientConnection;

                    try
                    {
                        clientConnection = await clientData.OpenAsync(token);
                    }
                    catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !token.IsCancellationRequested))
                    {
                        await serverData.DisposeAsync();
                        return await FailTransferAsync("425 Cannot open data connection.", token);
                    }

                    using (clientConnection)
                    {
                        using var transfer = CancellationTokenSource.CreateLinkedTokenSource(token);
                        var pump = PumpAsync(verb, serverData, clientConnection, transfer.Token);

                        if (await AbortRequestedAsync(pump, token))
                        {
                            await transfer.CancelAsync();
                            await serverData.DisposeAsync();
                            clientConnection.Dispose();
                            await ObserveAsync(pump);
                            return await AbortAsync(token);
                        }

                        if (!await ObserveAsync(pump))
                        {
                            // The client or the server dropped the data connection: the server's reply says what came of it.
                            await serverData.DisposeAsync();
                            clientConnection.Dispose();
                        }
                    }
                }
            }

            if (await _upstream.ReplyAsync(token) is not { } final)
            {
                await LostAsync(token);
                return false;
            }

            await _client.WriteReplyAsync(final, token);
            return final.Code != "421";
        }
    }

    private async Task PumpAsync(string verb, SslStream serverData, TcpClient clientConnection, CancellationToken token)
    {
        var clientStream = clientConnection.GetStream();

        if (Uploads.Contains(verb))
        {
            await clientStream.CopyToAsync(serverData, 128 * 1024, token);

            // close_notify: the server takes the end of the upload as the end of the file, not as a cut.
            await serverData.ShutdownAsync();
            return;
        }

        if (verb == "LIST")
        {
            await Rewrites.CopyListingAsync(serverData, clientStream, _serverZone, _clientZone, token);
        }
        else
        {
            await serverData.CopyToAsync(clientStream, 128 * 1024, token);
        }

        clientConnection.Client.Shutdown(SocketShutdown.Send);
    }

    /// <summary>True when the pump ran to its end; false when a data connection failed.</summary>
    private static async Task<bool> ObserveAsync(Task pump)
    {
        try
        {
            await pump;
            return true;
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException or AuthenticationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Waits for the transfer, watching the client's commands meanwhile: true when it sent ABOR (or
    /// went away). Any other command waits until the transfer is done, as on any server.
    /// </summary>
    private async Task<bool> AbortRequestedAsync(Task pump, CancellationToken token)
    {
        while (true)
        {
            using var watching = CancellationTokenSource.CreateLinkedTokenSource(token);
            var waiting = _commands.Reader.WaitToReadAsync(watching.Token).AsTask();

            if (await Task.WhenAny(pump, waiting) == pump)
            {
                await watching.CancelAsync();
                return false;
            }

            if (!await waiting)
            {
                return true;
            }

            while (_commands.Reader.TryRead(out var line))
            {
                if (Parse(line).Verb == "ABOR")
                {
                    return true;
                }

                _deferred.Enqueue(line);
            }
        }
    }

    /// <summary>Passes ABOR on and the server's replies back: 426 for the transfer, then 226 for the ABOR.</summary>
    private async Task<bool> AbortAsync(CancellationToken token)
    {
        await _upstream.SendAsync("ABOR", token);

        if (await _upstream.ReplyAsync(token) is not { } first)
        {
            await LostAsync(token);
            return false;
        }

        await _client.WriteReplyAsync(first, token);

        // The transfer's own reply and the ABOR's: the second, when there is one, follows at once.
        if (await _upstream.ReplyAsync(token, TimeSpan.FromSeconds(2)) is { } second)
        {
            await _client.WriteReplyAsync(second, token);
        }

        return true;
    }

    /// <summary>The server accepted a transfer the client then could not take: its reply to the cut is not the client's.</summary>
    private async Task<bool> FailTransferAsync(string reply, CancellationToken token)
    {
        if (await _upstream.ReplyAsync(token) is null)
        {
            await LostAsync(token);
            return false;
        }

        await ReplyAsync(reply, token);
        return true;
    }
}
