using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Channels;
using FtpServer.Direct;
using Microsoft.Extensions.Logging;

namespace FtpServer.Relay;

/// <summary>
/// One client: its commands go to its own connection to the FTPS server and the replies come back as
/// they are. Only what a plain client and a TLS server see differently is handled here: TLS commands,
/// HOST, the data connections, and the features and listings described in <see cref="Rewrites"/>.
/// </summary>
internal sealed class RelaySession(TcpClient client, RelayOptions options, PassivePorts ports, DirectFailures failures, DirectIdentity identity, ILogger logger)
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

    // The server offers DIRECT: RETR and STOR are first asked for as a direct transfer.
    private bool _direct;

    // The offset of the last accepted REST, which the server takes for a direct transfer it grants
    // and has to be given again when the relay then falls back to RETR or STOR.
    private long _restart;

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
                var loggedIn = false;

                var open = await ForwardAsync(line, token, reply =>
                {
                    if (reply.Code == "230")
                    {
                        loggedIn = true;
                        logger.LogInformation("{User} from {Client} logged in at {Host}", _user, _clientAddress, options.Upstream.Host);
                    }
                    else if (reply.Code == "530")
                    {
                        logger.LogWarning("{User} from {Client} was refused by {Host}", _user, _clientAddress, options.Upstream.Host);
                    }

                    return reply;
                });

                if (open && loggedIn && options.Direct)
                {
                    _direct = await OffersDirectAsync(token);
                }

                return open;

            case "REST":
                _restart = 0;

                return await ForwardAsync(line, token, reply =>
                {
                    if (reply.Code == "350" && long.TryParse(argument.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var offset))
                    {
                        _restart = offset;
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

            if (_direct && verb is "RETR" or "STOR")
            {
                if (await DirectAsync(verb, argument, clientData, token) is { } handled)
                {
                    _restart = 0;
                    return handled;
                }
            }

            // Any transfer uses up a REST, on the server as here.
            _restart = 0;

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

    /// <summary>
    /// Whether the server lists DIRECT among its features and takes the relay's key, asked once after the
    /// login: the machines it names then serve only a connection that shows that key.
    /// </summary>
    private async Task<bool> OffersDirectAsync(CancellationToken token)
    {
        if (!await DrainUnsolicitedAsync(token) || await _upstream.CommandAsync("FEAT", token) is not { Code: "211" } features ||
            !features.Lines.Any(x => Encoding.UTF8.GetString(x).Trim().Equals("DIRECT", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (await _upstream.CommandAsync($"SITE DIRECT KEY {identity.Fingerprint}", token) is not { Code: "200" })
        {
            logger.LogInformation("{Host} did not take the relay's key; transfers go through it", options.Upstream.Host);
            return false;
        }

        return true;
    }

    /// <summary>
    /// RETR or STOR as a direct transfer: SITE DIRECT asks the server where the file is, and the bytes
    /// go straight between that machine and the client. Null when it is not on offer for this file or
    /// the machine cannot be reached, after which the caller does the transfer through the server.
    /// </summary>
    private async Task<bool?> DirectAsync(string verb, string argument, ClientData clientData, CancellationToken token)
    {
        if (await _upstream.CommandAsync($"SITE DIRECT {verb} {argument}", token) is not { } reply)
        {
            await LostAsync(token);
            return false;
        }

        // Refused (an ASCII transfer, a file it does not know, a machine without direct transfers):
        // the server left everything as it was, REST included.
        if (reply.Code != "200" || !DirectTarget.TryParse(reply.Text, out var target))
        {
            return null;
        }

        var (direct, lost) = await ConnectDirectAsync(target, token);

        if (lost)
        {
            await LostAsync(token);
            return false;
        }

        if (direct is null)
        {
            return await RestoreRestartAsync(token) ? null : false;
        }

        long? length;

        await using (direct)
        {
            try
            {
                length = await direct.ReadStartAsync(options.DirectAnswerTimeout, token);
            }
            catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !token.IsCancellationRequested))
            {
                logger.LogWarning("A direct {Verb} of {Path} for {User} was refused, so it goes through the server: {Error}", verb, argument, _user, ex.Message);
                return await RestoreRestartAsync(token) ? null : false;
            }

            await ReplyAsync("150 Opening data connection.", token);

            TcpClient clientConnection;

            try
            {
                clientConnection = await clientData.OpenAsync(token);
            }
            catch (Exception ex) when (ex is IOException or SocketException || (ex is OperationCanceledException && !token.IsCancellationRequested))
            {
                await ReplyAsync("425 Cannot open data connection.", token);
                return true;
            }

            using (clientConnection)
            {
                var clientStream = clientConnection.GetStream();
                var stopwatch = Stopwatch.StartNew();
                using var transfer = CancellationTokenSource.CreateLinkedTokenSource(token);

                var pump = verb == "STOR"
                    ? direct.UploadAsync(clientStream, options.DirectAnswerTimeout, transfer.Token)
                    : DownloadAsync(direct, clientConnection, length ?? 0, transfer.Token);

                if (await AbortRequestedAsync(pump, token))
                {
                    await transfer.CancelAsync();
                    await direct.DisposeAsync();
                    clientConnection.Dispose();
                    await ObserveAsync(pump);
                    await ReplyAsync("426 Connection closed; transfer aborted.", token);
                    await ReplyAsync("226 Abort successful.", token);
                    return true;
                }

                try
                {
                    var bytes = await pump;
                    var seconds = Math.Max(stopwatch.Elapsed.TotalSeconds, 0.001);

                    logger.LogInformation("{User} {Verb} {Path} directly at {Address}: {Bytes} bytes in {Seconds:0.0} s ({Rate:0.0} MB/s)",
                        _user, verb, argument, direct.Address, bytes, seconds, bytes / seconds / 1_000_000);

                    // The server learns of an upload from the machine that wrote it; until it has, a client that
                    // goes on at once would not find the file. A server that does not know DONE answers 5xx.
                    if (verb == "STOR")
                    {
                        if (await _upstream.CommandAsync($"SITE DIRECT DONE {target.Token}", token) is not { } done)
                        {
                            await LostAsync(token);
                            return false;
                        }

                        if (done.Code.StartsWith('4'))
                        {
                            await ReplyAsync($"451 {done.Text}", token);
                            return true;
                        }
                    }

                    await ReplyAsync("226 Transfer complete.", token);
                }
                catch (DirectRefusedException ex)
                {
                    await ReplyAsync($"451 {ex.Message}", token);
                }
                catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException or AuthenticationException)
                {
                    logger.LogWarning("A direct {Verb} of {Path} for {User} broke off: {Error}", verb, argument, _user, ex.Message);
                    await ReplyAsync("426 Connection closed; transfer aborted.", token);
                }
            }

            return true;
        }
    }

    /// <summary>
    /// The machine over TCP at the addresses the server gave, or else over UDP, punching through both sides'
    /// NAT and firewall with the server passing on where each side can be reached. Null when neither works;
    /// a way that failed is skipped for a while. Lost when the server went away meanwhile.
    /// </summary>
    private async Task<(DirectConnection? Direct, bool Lost)> ConnectDirectAsync(DirectTarget target, CancellationToken token)
    {
        var tcp = "tcp:" + target.Key;

        if (!failures.IsFailing(tcp))
        {
            try
            {
                var direct = await DirectConnection.OpenAsync(target, identity, options.DirectConnectTimeout, token);
                failures.Succeed(tcp);
                return (direct, false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException || (ex is OperationCanceledException && !token.IsCancellationRequested))
            {
                failures.Fail(tcp);
                logger.LogWarning("Direct transfers to {Target} over TCP are skipped for {Minutes} minutes: {Error}", target.Key, DirectFailures.Duration.TotalMinutes, Describe(ex, options.DirectConnectTimeout));
            }
        }

        var udp = "udp:" + target.Key;

        if (!options.DirectUdp || failures.IsFailing(udp))
        {
            return (null, false);
        }

        UdpTunnel tunnel;

        try
        {
            tunnel = await UdpTunnel.OpenAsync(new UdpTunnelOptions { StunServers = options.StunServers }, token);
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            logger.LogWarning("No UDP port for a direct transfer: {Error}", ex.Message);
            return (null, false);
        }

        try
        {
            if (await _upstream.CommandAsync($"SITE DIRECT UDP {target.Token} {Candidates.Format(tunnel.Candidates)}", token) is not { } reply)
            {
                tunnel.Dispose();
                return (null, true);
            }

            // "200 key candidates"; anything else is a server or machine that does not do UDP.
            if (reply.Code != "200" || reply.Text.Split(' ', 2, StringSplitOptions.TrimEntries) is not [var key, var others] || Candidates.Parse(others) is not { Count: > 0 } peer)
            {
                tunnel.Dispose();
                return (null, false);
            }

            var stream = await tunnel.ConnectAsync(peer, key, options.DirectUdpTimeout, token);
            var connection = await DirectConnection.SecureAsync(stream, "UDP", target, identity, options.DirectUdpTimeout, token);
            failures.Succeed(udp);
            return (connection, false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException || (ex is OperationCanceledException && !token.IsCancellationRequested))
        {
            tunnel.Dispose();
            failures.Fail(udp);
            logger.LogWarning("Direct transfers to {Target} over UDP are skipped for {Minutes} minutes (NAT {Nat}): {Error}", target.Key, DirectFailures.Duration.TotalMinutes, tunnel.Nat, Describe(ex, options.DirectUdpTimeout));
            return (null, false);
        }
    }

    // A timeout surfaces as a cancellation, whose own message says nothing about what was waited for.
    private static string Describe(Exception ex, TimeSpan timeout) =>
        ex is OperationCanceledException ? $"no answer within {timeout.TotalSeconds:0.#} s" : ex.Message;

    private static async Task<long> DownloadAsync(DirectConnection direct, TcpClient clientConnection, long length, CancellationToken token)
    {
        var bytes = await direct.DownloadAsync(clientConnection.GetStream(), length, token);
        clientConnection.Client.Shutdown(SocketShutdown.Send);
        return bytes;
    }

    /// <summary>Gives the server the REST it took for a direct transfer the relay did not make; false when the server is gone.</summary>
    private async Task<bool> RestoreRestartAsync(CancellationToken token)
    {
        if (_restart <= 0)
        {
            return true;
        }

        if (await _upstream.CommandAsync($"REST {_restart.ToString(CultureInfo.InvariantCulture)}", token) is not { } reply)
        {
            await LostAsync(token);
            return false;
        }

        return true;
    }

    private async Task PumpAsync(string verb, SslStream serverData, TcpClient clientConnection, CancellationToken token)
    {
        var clientStream = clientConnection.GetStream();

        if (Uploads.Contains(verb))
        {
            await clientStream.CopyToAsync(serverData, 128 * 1024, token);

            // close_notify: the server takes the end of the upload as the end of the file, not as a cut.
            await serverData.ShutdownAsync();

            // Then wait for the server to close its side: closing while what it sent (a TLS session ticket) is
            // still unread here resets the connection, and the server may lose the end of the file to that.
            await DrainAsync(serverData, token);
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

    private static async Task DrainAsync(SslStream serverData, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var buffer = new byte[4096];

        try
        {
            while (await serverData.ReadAsync(buffer, timeout.Token) > 0)
            {
            }
        }
        catch (Exception ex) when (ex is IOException || (ex is OperationCanceledException && !token.IsCancellationRequested))
        {
            // Closed without close_notify, or not at all: the server's reply says how the upload went.
        }
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
