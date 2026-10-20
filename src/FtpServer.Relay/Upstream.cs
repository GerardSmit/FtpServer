using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace FtpServer.Relay;

/// <summary>
/// One client's connection to the FTPS server: explicit TLS on the control connection (AUTH TLS),
/// and every data connection protected (PBSZ 0, PROT P) before the client sends its first command.
/// </summary>
internal sealed class Upstream : IAsyncDisposable
{
    private readonly UpstreamOptions _options;
    private readonly TcpClient _tcp;
    private readonly LineChannel _control;

    private Upstream(UpstreamOptions options, TcpClient tcp, LineChannel control, FtpReply greeting)
    {
        _options = options;
        _tcp = tcp;
        _control = control;
        Greeting = greeting;
    }

    /// <summary>The server's greeting, which the client gets as its own.</summary>
    public FtpReply Greeting { get; }

    public TimeSpan Timeout => TimeSpan.FromSeconds(_options.TimeoutSeconds);

    public static async Task<Upstream> ConnectAsync(UpstreamOptions options, CancellationToken token)
    {
        var tcp = new TcpClient { NoDelay = true };

        try
        {
            using (var connecting = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                connecting.CancelAfter(TimeSpan.FromSeconds(15));
                await tcp.ConnectAsync(options.Host, options.Port, connecting.Token);
            }

            var control = new LineChannel(tcp.GetStream());
            var greeting = await Expect(control, "220", token);

            await control.WriteLineAsync("AUTH TLS", token);
            await Expect(control, "234", token);

            var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await tls.AuthenticateAsClientAsync(ClientOptions(options), token);
            control.Replace(tls);

            await control.WriteLineAsync("PBSZ 0", token);
            await Expect(control, "200", token);
            await control.WriteLineAsync("PROT P", token);
            await Expect(control, "200", token);

            return new Upstream(options, tcp, control, greeting);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private static async Task<FtpReply> Expect(LineChannel control, string code, CancellationToken token)
    {
        var reply = await control.ReadReplyAsync(token) ?? throw new IOException("The server closed the connection.");
        return reply.Code == code ? reply : throw new IOException($"The server answered: {System.Text.Encoding.UTF8.GetString(reply.Lines[^1])}");
    }

    internal static SslClientAuthenticationOptions ClientOptions(UpstreamOptions options) => new()
    {
        TargetHost = options.Host,
        RemoteCertificateValidationCallback = (_, certificate, _, errors) => Accepts(options, certificate, errors)
    };

    /// <summary>A certificate that validates for the host, or the one the configuration pins.</summary>
    private static bool Accepts(UpstreamOptions options, X509Certificate? certificate, SslPolicyErrors errors) =>
        errors == SslPolicyErrors.None ||
        (certificate is not null &&
         options.CertificateThumbprint?.Replace(" ", string.Empty) is { Length: > 0 } thumbprint &&
         string.Equals(certificate.GetCertHashString(), thumbprint, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Whether the server has said something nobody asked for, such as a 421 before it closes an idle
    /// connection: read before the next command, so its reply is not mistaken for this one.
    /// </summary>
    public bool HasUnsolicited => _control.HasBuffered || _tcp.Available > 0;

    public Task SendAsync(ReadOnlyMemory<byte> line, CancellationToken token) => _control.WriteLineAsync(line, token);

    public Task SendAsync(string line, CancellationToken token) => _control.WriteLineAsync(line, token);

    /// <summary>The next reply; null when the server closed the connection or did not answer in time.</summary>
    public async Task<FtpReply?> ReplyAsync(CancellationToken token, TimeSpan? timeout = null)
    {
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(token);
        waiting.CancelAfter(timeout ?? Timeout);

        try
        {
            return await _control.ReadReplyAsync(waiting.Token);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            return null;
        }
    }

    public async Task<FtpReply?> CommandAsync(string line, CancellationToken token)
    {
        await SendAsync(line, token);
        return await ReplyAsync(token);
    }

    /// <summary>
    /// Opens a passive data connection, still without TLS: the TLS handshake follows once the server
    /// accepted the transfer command. The port comes from EPSV (or PASV); the address is the one the
    /// control connection reached, as the server's own idea of it may not be reachable from here.
    /// </summary>
    public async Task<TcpClient> OpenDataAsync(CancellationToken token)
    {
        var port = await PassivePortAsync(token);
        // A dual-stack control socket reports an IPv4 server as ::ffff:a.b.c.d, which an IPv4 socket cannot dial.
        var address = ClientData.Normalize(((IPEndPoint)_tcp.Client.RemoteEndPoint!).Address);
        var data = new TcpClient(address.AddressFamily) { NoDelay = true };

        try
        {
            using var connecting = CancellationTokenSource.CreateLinkedTokenSource(token);
            connecting.CancelAfter(TimeSpan.FromSeconds(15));
            await data.ConnectAsync(address, port, connecting.Token);
            return data;
        }
        catch
        {
            data.Dispose();
            throw;
        }
    }

    private async Task<int> PassivePortAsync(CancellationToken token)
    {
        // "229 Entering Extended Passive Mode (|||port|)"
        if (await CommandAsync("EPSV", token) is { Code: "229" } extended &&
            extended.Text.Split('|') is [_, _, _, var epsvPort, ..] &&
            int.TryParse(epsvPort, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
        {
            return port;
        }

        // "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
        var passive = await CommandAsync("PASV", token);

        if (passive is { Code: "227" } &&
            passive.Text.IndexOf('(') is >= 0 and var open &&
            passive.Text.IndexOf(')', open) is >= 0 and var close &&
            passive.Text[(open + 1)..close].Split(',') is [_, _, _, _, var high, var low] &&
            int.TryParse(high, NumberStyles.None, CultureInfo.InvariantCulture, out var h) &&
            int.TryParse(low, NumberStyles.None, CultureInfo.InvariantCulture, out var l))
        {
            return (h << 8) | l;
        }

        throw new IOException(passive is null ? "The server did not answer PASV." : $"The server refused PASV: {passive.Text}");
    }

    /// <summary>Protects a data connection the server accepted a transfer on (PROT P).</summary>
    public async Task<SslStream> ProtectAsync(TcpClient data, CancellationToken token)
    {
        var tls = new SslStream(data.GetStream(), leaveInnerStreamOpen: false);

        using var handshake = CancellationTokenSource.CreateLinkedTokenSource(token);
        handshake.CancelAfter(TimeSpan.FromSeconds(15));
        await tls.AuthenticateAsClientAsync(ClientOptions(_options), handshake.Token);

        return tls;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _control.Stream.DisposeAsync();
        }
        catch (IOException)
        {
        }

        _tcp.Dispose();
    }
}
