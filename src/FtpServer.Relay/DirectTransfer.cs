using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FtpServer.Relay;

/// <summary>
/// Where a server says a file can be fetched or sent directly, as its reply to SITE DIRECT:
/// <c>direct://address1,address2:port/token?sha256=fingerprint</c>. The machine at those addresses
/// holds the file and serves it over TLS with a certificate of its own, which the fingerprint pins.
/// </summary>
internal sealed record DirectTarget(IReadOnlyList<string> Addresses, int Port, string Token, byte[] Fingerprint)
{
    private const string Scheme = "direct://";

    /// <summary>The addresses and port, to remember a target that could not be reached.</summary>
    public string Key => string.Join(',', Addresses) + ":" + Port.ToString(CultureInfo.InvariantCulture);

    public static bool TryParse(string text, [NotNullWhen(true)] out DirectTarget? target)
    {
        target = null;
        text = text.Trim();

        if (!text.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rest = text[Scheme.Length..];
        var slash = rest.IndexOf('/');
        var query = rest.IndexOf('?');

        if (slash <= 0 || query <= slash)
        {
            return false;
        }

        var authority = rest[..slash];
        var token = rest[(slash + 1)..query];

        // The port follows the last colon outside brackets, so an IPv6 address may carry its own.
        var colon = authority.LastIndexOf(':');

        if (colon <= 0 || authority.IndexOf(']', colon) >= 0 ||
            !int.TryParse(authority[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            return false;
        }

        var addresses = authority[..colon]
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => x.Trim('[', ']'))
            .Where(x => x.Length > 0)
            .ToList();

        byte[]? fingerprint = null;

        foreach (var pair in rest[(query + 1)..].Split('&'))
        {
            if (pair.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    fingerprint = Convert.FromHexString(pair["sha256=".Length..].Replace(":", ""));
                }
                catch (FormatException)
                {
                    return false;
                }
            }
        }

        if (addresses.Count == 0 || fingerprint is not { Length: 32 } || token.Length is < 16 or > 128 || !token.All(char.IsAsciiHexDigit))
        {
            return false;
        }

        target = new DirectTarget(addresses, port, token, fingerprint);
        return true;
    }
}

/// <summary>
/// The key pair the relay shows the machines it transfers with directly, made anew at every start. The
/// server is told its fingerprint over the FTPS connection (SITE DIRECT KEY), and a machine only serves a
/// grant to the key the server named, so a token that leaks is of no use to anyone else.
/// </summary>
internal sealed class DirectIdentity : IDisposable
{
    private DirectIdentity(X509Certificate2 certificate)
    {
        Certificate = certificate;
        Fingerprint = Convert.ToHexStringLower(certificate.GetCertHash(HashAlgorithmName.SHA256));
    }

    public X509Certificate2 Certificate { get; }

    /// <summary>SHA-256 of the certificate, in hex.</summary>
    public string Fingerprint { get; }

    public static DirectIdentity Create()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=ftp-relay", key, HashAlgorithmName.SHA256);
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        // Through PKCS#12: on Windows, TLS only presents a certificate whose key is not ephemeral.
        return new DirectIdentity(X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null));
    }

    public void Dispose() => Certificate.Dispose();
}

/// <summary>
/// One direct transfer. The client sends the token on a line of its own; the other side answers
/// <c>OK length</c> and sends that many bytes (a download), or <c>OK</c> and takes the file in frames
/// of a 4-byte big-endian length and that many bytes, ended by an empty frame, after which it answers
/// <c>OK length</c> (an upload). A refusal is <c>ERR message</c>.
/// </summary>
internal sealed class DirectConnection : IAsyncDisposable
{
    private const int MaxFrame = 1024 * 1024;

    private readonly SslStream _tls;

    private DirectConnection(SslStream tls, string address)
    {
        _tls = tls;
        Address = address;
    }

    /// <summary>The address that answered first, or how the connection was made.</summary>
    public string Address { get; }

    /// <summary>
    /// Connects to whichever address answers first within <paramref name="connectTimeout"/>, then as
    /// <see cref="SecureAsync"/>. Throws when none could be reached.
    /// </summary>
    public static async Task<DirectConnection> OpenAsync(DirectTarget target, DirectIdentity identity, TimeSpan connectTimeout, CancellationToken token)
    {
        using var connecting = CancellationTokenSource.CreateLinkedTokenSource(token);
        connecting.CancelAfter(connectTimeout);

        var (tcp, address) = await ConnectFirstAsync(target, connecting.Token);
        return await SecureAsync(tcp.GetStream(), address, target, identity, connectTimeout, token);
    }

    /// <summary>
    /// TLS over <paramref name="stream"/>, which it then owns: the machine's certificate is checked
    /// against the target's fingerprint, the relay shows its own, and the token is sent.
    /// </summary>
    public static async Task<DirectConnection> SecureAsync(Stream stream, string address, DirectTarget target, DirectIdentity identity, TimeSpan timeout, CancellationToken token)
    {
        var tls = new SslStream(stream, leaveInnerStreamOpen: false);

        try
        {
            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(token);
            handshake.CancelAfter(timeout);

            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "direct",
                LocalCertificateSelectionCallback = (_, _, _, _, _) => identity.Certificate,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                    certificate is not null &&
                    CryptographicOperations.FixedTimeEquals(certificate.GetCertHash(HashAlgorithmName.SHA256), target.Fingerprint)
            }, handshake.Token);

            await tls.WriteAsync(Encoding.ASCII.GetBytes(target.Token + "\n"), token);
            await tls.FlushAsync(token);

            return new DirectConnection(tls, address);
        }
        catch
        {
            await tls.DisposeAsync();
            throw;
        }
    }

    private static async Task<(TcpClient Client, string Address)> ConnectFirstAsync(DirectTarget target, CancellationToken token)
    {
        using var race = CancellationTokenSource.CreateLinkedTokenSource(token);
        var attempts = target.Addresses.Select(address => ConnectAsync(address, target.Port, race.Token)).ToList();
        Exception? last = null;

        while (attempts.Count > 0)
        {
            var done = await Task.WhenAny(attempts);
            attempts.Remove(done);

            try
            {
                var winner = await done;
                await race.CancelAsync();

                // The others are cancelled; one that still got through is not needed.
                _ = Task.WhenAll(attempts).ContinueWith(static finished =>
                {
                    if (finished.IsCompletedSuccessfully)
                    {
                        foreach (var (client, _) in finished.Result)
                        {
                            client.Dispose();
                        }
                    }
                }, TaskScheduler.Default);

                return winner;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                last = ex;
            }
        }

        token.ThrowIfCancellationRequested();
        throw new IOException("None of the addresses answered.", last);
    }

    private static async Task<(TcpClient, string)> ConnectAsync(string address, int port, CancellationToken token)
    {
        var client = new TcpClient(AddressFamily.InterNetworkV6) { NoDelay = true };
        client.Client.DualMode = true;

        try
        {
            await client.ConnectAsync(address, port, token);
            return (client, address);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    /// <summary>The answer to the token: the length of a download, or null for an upload's go-ahead.</summary>
    public async Task<long?> ReadStartAsync(TimeSpan timeout, CancellationToken token)
    {
        var line = await ReadLineAsync(timeout, token);

        if (line == "OK")
        {
            return null;
        }

        if (line.StartsWith("OK ", StringComparison.Ordinal) &&
            long.TryParse(line[3..], NumberStyles.None, CultureInfo.InvariantCulture, out var length))
        {
            return length;
        }

        throw new DirectRefusedException(line.StartsWith("ERR ", StringComparison.Ordinal) ? line[4..] : line);
    }

    /// <summary>Copies a download of <paramref name="length"/> bytes; throws when it ends short.</summary>
    public async Task<long> DownloadAsync(Stream target, long length, CancellationToken token)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);

        try
        {
            var remaining = length;

            while (remaining > 0)
            {
                var read = await _tls.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), token);

                if (read == 0)
                {
                    throw new IOException($"The transfer ended after {length - remaining} of {length} bytes.");
                }

                await target.WriteAsync(buffer.AsMemory(0, read), token);
                remaining -= read;
            }

            return length;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Sends <paramref name="source"/> to its end and returns the length the other side stored.</summary>
    public async Task<long> UploadAsync(Stream source, TimeSpan timeout, CancellationToken token)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4 + 128 * 1024);

        try
        {
            int read;

            while ((read = await source.ReadAsync(buffer.AsMemory(4, Math.Min(buffer.Length - 4, MaxFrame)), token)) > 0)
            {
                BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)read);
                await _tls.WriteAsync(buffer.AsMemory(0, 4 + read), token);
            }

            BinaryPrimitives.WriteUInt32BigEndian(buffer, 0);
            await _tls.WriteAsync(buffer.AsMemory(0, 4), token);
            await _tls.FlushAsync(token);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        // The answer comes once the file is written, which for a large one takes a moment.
        return await ReadStartAsync(timeout, token) ?? throw new IOException("The upload was not confirmed.");
    }

    /// <summary>A line of ASCII, read a byte at a time so nothing after it is taken from the stream.</summary>
    private async Task<string> ReadLineAsync(TimeSpan timeout, CancellationToken token)
    {
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(token);
        waiting.CancelAfter(timeout);

        var line = new StringBuilder();
        var one = new byte[1];

        while (line.Length < 1024)
        {
            if (await _tls.ReadAsync(one, waiting.Token) == 0)
            {
                throw new IOException("The connection closed before an answer.");
            }

            if (one[0] == '\n')
            {
                return line.ToString().TrimEnd('\r');
            }

            line.Append((char)one[0]);
        }

        throw new IOException("The answer is too long.");
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _tls.DisposeAsync();
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>The other side refused the transfer, with its reason.</summary>
internal sealed class DirectRefusedException(string message) : IOException(message);

/// <summary>
/// Ways to a target that did not work, skipped for a while, so a machine the relay cannot reach costs
/// the wait once and not for every file. A way is how ("tcp:" or "udp:") followed by the target's key.
/// </summary>
internal sealed class DirectFailures(TimeProvider time)
{
    public static readonly TimeSpan Duration = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _until = new();

    public bool IsFailing(string way) =>
        _until.TryGetValue(way, out var until) && until > time.GetUtcNow();

    public void Fail(string way) => _until[way] = time.GetUtcNow() + Duration;

    public void Succeed(string way) => _until.TryRemove(way, out _);
}
