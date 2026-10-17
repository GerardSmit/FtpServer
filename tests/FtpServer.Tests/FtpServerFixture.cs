using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using FtpServer.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer.Tests;

/// <summary>
/// Runs a real server on a loopback port against a temporary root.
/// </summary>
public sealed class FtpServerFixture : IAsyncDisposable
{
    private readonly IHost _host;

    public string Root { get; }

    public int Port { get; }

    public IServiceProvider Services => _host.Services;

    private FtpServerFixture(IHost host, string root, int port)
    {
        _host = host;
        Root = root;
        Port = port;
    }

    public static async Task<FtpServerFixture> StartAsync(
        Action<FtpOptions>? configure = null,
        Action<IServiceCollection>? configureServices = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "ftptest-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);

        // Tests run in parallel, so the control port and the passive range must not be guessed
        // from one another: a neighbouring fixture's passive range would otherwise routinely
        // cover this one's control port.
        var (port, passiveStart, passiveEnd) = ReservePorts();

        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Logging.SetMinimumLevel(LogLevel.None);

        builder.Services.AddFtpServer(options =>
        {
            options.Port = port;
            options.Path = root;
            options.Passive = true;
            options.Authentication.AllowAnonymous = true;
            options.Authentication.AnonymousCanWrite = true;
            options.Authentication.FailureDelay = TimeSpan.Zero;
            options.PassivePortRange.Start = passiveStart;
            options.PassivePortRange.End = passiveEnd;

            configure?.Invoke(options);
        });

        // After AddFtpServer, so a test can replace a service the defaults registered with
        // TryAddSingleton - the authenticator in particular.
        configureServices?.Invoke(builder.Services);

        var host = builder.Build();
        await host.StartAsync();

        return new FtpServerFixture(host, root, port);
    }

    /// <summary>Hands every fixture in this process its own passive range.</summary>
    private static int _passiveBlock = -1;

    /// <summary>
    /// Base of the passive ranges. Deliberately below the OS ephemeral range (49152+ on Windows,
    /// 32768+ on Linux) so that a control port, which is allocated ephemerally, can never land
    /// inside another fixture's passive range.
    /// </summary>
    private const int PassiveBase = 21000;

    private const int PassiveBlockSize = 16;

    /// <summary>
    /// Allocates a control port and a passive range that no other fixture in this process shares.
    /// </summary>
    /// <remarks>
    /// Probing for a free contiguous block does not work under xunit's parallelism: two fixtures
    /// probing at the same moment get adjacent ephemeral ports and claim overlapping ranges.
    /// A monotonic counter gives disjoint ranges by construction.
    /// </remarks>
    private static (int Control, int PassiveStart, int PassiveEnd) ReservePorts()
    {
        var block = Interlocked.Increment(ref _passiveBlock);
        var start = PassiveBase + (block * PassiveBlockSize);

        if (start + PassiveBlockSize > 32000)
        {
            throw new InvalidOperationException("Ran out of reserved passive port blocks for tests.");
        }

        using var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        control.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        return (((IPEndPoint)control.LocalEndPoint!).Port, start, start + PassiveBlockSize - 1);
    }

    public string WriteFile(string relativePath, string content)
    {
        var full = Path.Combine(Root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content);
        return full;
    }

    public async Task<FtpTestClient> ConnectAsync()
    {
        var client = new FtpTestClient(Port);
        await client.ConnectAsync();
        return client;
    }

    public async Task<FtpTestClient> LoginAsync()
    {
        var client = await ConnectAsync();
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        return client;
    }

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync(TimeSpan.FromSeconds(5));
        _host.Dispose();

        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
            // A file may still be held open on Windows; the temp directory will be cleaned up
            // by the OS eventually.
        }
    }
}

/// <summary>
/// Minimal raw-protocol client. Deliberately not a real FTP library, so a test can send exactly
/// the bytes it wants - including malformed ones.
/// </summary>
public sealed class FtpTestClient(int port, bool implicitTls = false) : IAsyncDisposable
{
    private readonly TcpClient _client = new();
    private Stream _stream = Stream.Null;

    public string Banner { get; private set; } = string.Empty;

    public async Task ConnectAsync()
    {
        await _client.ConnectAsync(IPAddress.Loopback, port);
        _stream = _client.GetStream();

        // Implicit FTPS: the handshake comes first, and even the greeting arrives protected.
        if (implicitTls)
        {
            await StartTlsAsync();
        }

        Banner = await ReadReplyAsync("the greeting");
    }

    /// <summary>Sends raw bytes and returns the reply, plus anything pipelined behind it.</summary>
    /// <remarks>
    /// The reply is waited for rather than sampled. A read that gave up early used to return what
    /// it had - often nothing - which does not fail there and then: the reply arrives during the
    /// next command instead, every later assertion is one reply out of step, and the test that
    /// fails is not the test that went wrong. Whatever the underlying delay, it should be reported
    /// against the command that suffered it.
    /// </remarks>
    public async Task<string> SendRawAsync(string text, int settleMs = 250)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        await _stream.WriteAsync(bytes);
        await _stream.FlushAsync();

        // The settle window is for replies the server sends unprompted after the first one - it is
        // not what makes the first reply arrive.
        await Task.Delay(settleMs);

        return await ReadReplyAsync(text.TrimEnd('\r', '\n'));
    }

    public Task<string> SendAsync(string command, int settleMs = 250) => SendRawAsync(command + "\r\n", settleMs);

    /// <summary>
    /// Reads one complete reply, and fails the test rather than letting the stream fall out of
    /// step if none arrives - or if only part of one does, which desynchronises it just as surely.
    /// </summary>
    private async Task<string> ReadReplyAsync(string what)
    {
        var reply = await ReadAsync(ReplyTimeoutMs);

        if (!IsCompleteReply(reply))
        {
            throw new TimeoutException(
                $"No complete reply to '{what}' within {ReplyTimeoutMs} ms. " +
                $"Received: '{reply.ReplaceLineEndings("\\r\\n")}'.");
        }

        return reply;
    }

    /// <summary>
    /// How long a single reply may take. Generous on purpose: this is a deadlock detector, not a
    /// performance assertion, and the suite runs its fixtures in parallel on shared CI hardware.
    /// </summary>
    private const int ReplyTimeoutMs = 30_000;

    /// <summary>
    /// Sends exact bytes and returns the reply byte for byte.
    /// </summary>
    /// <remarks>
    /// The string overloads encode as UTF-8, which cannot express a lone 0xFF or a malformed
    /// sequence - the cases where the bytes on the wire are the point of the test.
    /// </remarks>
    public async Task<byte[]> SendBytesAsync(byte[] bytes, int settleMs = 250)
    {
        await _stream.WriteAsync(bytes);
        await _stream.FlushAsync();
        await Task.Delay(settleMs);

        var buffer = new byte[64 * 1024];
        using var received = new MemoryStream();
        using var cts = new CancellationTokenSource(2000);

        try
        {
            while (true)
            {
                var read = await _stream.ReadAsync(buffer, cts.Token);

                if (read == 0)
                {
                    break;
                }

                received.Write(buffer, 0, read);

                if (received.Length > 0)
                {
                    using var quiet = new CancellationTokenSource(200);

                    try
                    {
                        read = await _stream.ReadAsync(buffer, quiet.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (read == 0)
                    {
                        break;
                    }

                    received.Write(buffer, 0, read);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Deadline reached; return whatever arrived.
        }

        return received.ToArray();
    }

    /// <summary>
    /// Reads until a complete FTP reply has arrived and the server then goes quiet.
    /// </summary>
    /// <remarks>
    /// Waiting on a silence gap alone was timing-dependent: under parallel load a reply could
    /// straddle the window and be attributed to the next command. The trailing quiet period is
    /// still there, so deliberately-pipelined replies accumulate.
    /// </remarks>
    public async Task<string> ReadAsync(int timeoutMs = 5000)
    {
        var buffer = new byte[64 * 1024];
        var builder = new StringBuilder();
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);

        while (DateTime.UtcNow < deadline)
        {
            var remaining = (int)Math.Max(1, (deadline - DateTime.UtcNow).TotalMilliseconds);
            var slice = IsCompleteReply(builder) ? Math.Min(200, remaining) : remaining;

            using var cts = new CancellationTokenSource(slice);

            int read;

            try
            {
                read = await _stream.ReadAsync(buffer, cts.Token);
            }
            catch (OperationCanceledException)
            {
                // Quiet: done if a whole reply is in hand, otherwise the deadline decides.
                if (IsCompleteReply(builder))
                {
                    break;
                }

                continue;
            }
            catch (IOException)
            {
                break;
            }

            if (read == 0)
            {
                break;
            }

            builder.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }

        return builder.ToString();
    }

    private static bool IsCompleteReply(StringBuilder builder) => IsCompleteReply(builder.ToString());

    /// <summary>A reply ends with a line whose 3-digit code is followed by a space, not a dash.</summary>
    private static bool IsCompleteReply(string text)
    {
        if (!text.EndsWith("\r\n", StringComparison.Ordinal))
        {
            return false;
        }

        var lines = text.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        if (lines.Length == 0)
        {
            return false;
        }

        var last = lines[^1];

        return last.Length >= 4 &&
               char.IsAsciiDigit(last[0]) && char.IsAsciiDigit(last[1]) && char.IsAsciiDigit(last[2]) &&
               last[3] == ' ';
    }

    /// <summary>
    /// Distinguishes a closed connection from a quiet one. <see cref="ReadAsync"/> returns an
    /// empty string for both end-of-stream and a read timeout, so it cannot be used to prove the
    /// server actually closed the socket.
    /// </summary>
    public async Task<bool> IsClosedAsync(int timeoutMs = 2000)
    {
        var buffer = new byte[1];
        using var cts = new CancellationTokenSource(timeoutMs);

        try
        {
            return await _stream.ReadAsync(buffer, cts.Token) == 0;
        }
        catch (OperationCanceledException)
        {
            return false; // still open, just silent
        }
        catch (IOException)
        {
            return true; // reset counts as closed
        }
    }

    /// <summary>Upgrades the control connection after AUTH TLS.</summary>
    public async Task StartTlsAsync(string targetHost = "localhost")
    {
        var ssl = new SslStream(_stream, leaveInnerStreamOpen: false, static (_, _, _, _) => true);

        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            // Sent as the SNI server name, which a HOST command has to agree with.
            TargetHost = targetHost,
        });

        RemoteCertificate = ssl.RemoteCertificate;
        _stream = ssl;
    }

    /// <summary>The certificate the server presented in the last handshake.</summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate? RemoteCertificate { get; private set; }

    /// <summary>
    /// Returns to reading and writing in the clear, as the server does after REIN.
    /// </summary>
    /// <remarks>
    /// The SslStream is abandoned rather than disposed: disposing it writes close_notify to a
    /// connection the server has already stopped treating as protected.
    /// </remarks>
    public void StopTls() => _stream = _client.GetStream();

    /// <summary>Issues PASV and opens the data connection it advertises.</summary>
    public async Task<TcpClient> OpenPassiveAsync()
    {
        var reply = await SendAsync("PASV");
        var match = System.Text.RegularExpressions.Regex.Match(reply, @"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)");

        if (!match.Success)
        {
            throw new InvalidOperationException("PASV failed: " + reply);
        }

        var dataPort = (int.Parse(match.Groups[5].Value) << 8) + int.Parse(match.Groups[6].Value);

        var data = new TcpClient();
        await data.ConnectAsync(IPAddress.Loopback, dataPort);
        return data;
    }

    /// <summary>
    /// Listens locally, announces the port with PORT, and returns the accepted connection —
    /// i.e. an active-mode data transfer, where the server dials out to us.
    /// </summary>
    public async Task<(byte[] Data, string Control)> DownloadActiveAsync(string command)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var address = IPAddress.Loopback.GetAddressBytes();

        var reply = await SendAsync($"PORT {address[0]},{address[1]},{address[2]},{address[3]},{port >> 8},{port & 0xFF}");

        if (!reply.StartsWith("200", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("PORT failed: " + reply);
        }

        var accept = listener.AcceptTcpClientAsync();

        await _stream.WriteAsync(Encoding.UTF8.GetBytes(command + "\r\n"));
        await _stream.FlushAsync();

        using var data = await accept.WaitAsync(TimeSpan.FromSeconds(10));

        using var buffer = new MemoryStream();
        await data.GetStream().CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));
        data.Close();

        await Task.Delay(250);
        return (buffer.ToArray(), await ReadReplyAsync(command));
    }

    /// <summary>Runs a command that sends data to the client, returning the payload and the replies.</summary>
    public async Task<(byte[] Data, string Control)> DownloadAsync(string command)
    {
        using var data = await OpenPassiveAsync();

        await _stream.WriteAsync(Encoding.UTF8.GetBytes(command + "\r\n"));
        await _stream.FlushAsync();

        using var buffer = new MemoryStream();

        // Bounded: a regression that wedges a transfer must fail the test, not hang the run.
        await data.GetStream().CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));
        data.Close();

        await Task.Delay(250);
        return (buffer.ToArray(), await ReadReplyAsync(command));
    }

    /// <summary>Runs a command that receives data from the client.</summary>
    public async Task<string> UploadAsync(string command, byte[] payload)
    {
        using var data = await OpenPassiveAsync();

        await _stream.WriteAsync(Encoding.UTF8.GetBytes(command + "\r\n"));
        await _stream.FlushAsync();
        await Task.Delay(150);

        await data.GetStream().WriteAsync(payload);
        await data.GetStream().FlushAsync();
        data.Close();

        await Task.Delay(300);
        return await ReadReplyAsync(command);
    }

    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync();
        _client.Dispose();
    }
}
