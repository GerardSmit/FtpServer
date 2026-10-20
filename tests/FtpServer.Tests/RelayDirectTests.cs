using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FtpServer.Extensions;
using FtpServer.Handlers;
using FtpServer.Options;
using FtpServer.Relay;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer.Tests;

/// <summary>
/// Direct transfers through the relay: the server answers SITE DIRECT with where the file can be had,
/// and the relay moves the bytes between that machine and the client, or falls back to the server.
/// </summary>
public sealed class RelayDirectTests : IAsyncLifetime
{
    private const string User = "jan";
    private const string Password = "relay-secret";

    private readonly FakeDirectServer _direct = new();
    private FtpServerFixture _upstream = null!;
    private IHost? _relay;

    public async ValueTask InitializeAsync()
    {
        _direct.Start();

        _upstream = await FtpServerFixture.StartAsync(o =>
        {
            o.Ftps = true;
            o.RequireTls = true;
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new FtpUserOptions { Name = User, Password = Password });
        }, services =>
        {
            services.AddSingleton<IFtpSiteCommand>(new DirectCommand(this));
            services.AddSingleton<IFtpFeatureProvider, DirectFeature>();
        });

        _upstream.WriteFile("site/bin/app.dll", "0123456789");
    }

    public async ValueTask DisposeAsync()
    {
        if (_relay is not null)
        {
            await _relay.StopAsync();
            _relay.Dispose();
        }

        await _upstream.DisposeAsync();
        _direct.Dispose();
    }

    /// <summary>What the server's DIRECT answers: the address the relay is told to use, or a refusal.</summary>
    private string DirectAddress { get; set; } = "127.0.0.1";

    private bool RefuseDirect { get; set; }

    private async Task<FtpTestClient> ConnectAsync()
    {
        var thumbprint = _upstream.Services.GetRequiredService<CertificateProvider>().GetCertificate().Thumbprint;
        var (_, passiveStart, passiveEnd) = FtpServerFixture.ReservePorts();

        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Logging.SetMinimumLevel(LogLevel.None);
        builder.Services.AddFtpRelay(new RelayOptions
        {
            ListenAddress = "127.0.0.1",
            Port = 0,
            PassivePortStart = passiveStart,
            PassivePortEnd = passiveEnd,
            DirectConnectTimeout = TimeSpan.FromSeconds(1),
            Upstream = new UpstreamOptions { Host = "localhost", Port = _upstream.Port, CertificateThumbprint = thumbprint, TimeoutSeconds = 15 }
        });

        _relay = builder.Build();
        await _relay.StartAsync();

        var server = _relay.Services.GetRequiredService<RelayServer>();
        await server.Listening;

        var client = new FtpTestClient(server.Port);
        await client.ConnectAsync();
        await client.SendAsync($"USER {User}");
        Assert.StartsWith("230", await client.SendAsync($"PASS {Password}"));
        Assert.StartsWith("200", await client.SendAsync("TYPE I"));
        return client;
    }

    private string Upstream(string relative) => Path.Combine(_upstream.Root, relative);

    [Fact]
    public async Task A_download_comes_straight_from_the_machine_that_holds_it()
    {
        await using var client = await ConnectAsync();

        var (data, control) = await client.DownloadAsync("RETR /site/bin/app.dll");

        Assert.Equal("0123456789", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
        Assert.Equal(1, _direct.Served);
    }

    [Fact]
    public async Task A_resumed_download_starts_where_rest_said()
    {
        await using var client = await ConnectAsync();

        Assert.StartsWith("350", await client.SendAsync("REST 4"));
        var (data, _) = await client.DownloadAsync("RETR /site/bin/app.dll");

        Assert.Equal("456789", Encoding.ASCII.GetString(data));
        Assert.Equal(1, _direct.Served);
    }

    [Fact]
    public async Task An_upload_lands_through_the_machine_that_holds_it()
    {
        await using var client = await ConnectAsync();

        var control = await client.UploadAsync("STOR /site/new.txt", "hello"u8.ToArray());

        Assert.Contains("226", control);
        Assert.Equal("hello", File.ReadAllText(Upstream("site/new.txt")));
        Assert.Equal(1, _direct.Served);
    }

    [Fact]
    public async Task A_refused_direct_transfer_goes_through_the_server()
    {
        RefuseDirect = true;
        await using var client = await ConnectAsync();

        var (data, _) = await client.DownloadAsync("RETR /site/bin/app.dll");

        Assert.Equal("0123456789", Encoding.ASCII.GetString(data));
        Assert.Equal(0, _direct.Served);
    }

    [Fact]
    public async Task A_machine_that_cannot_be_reached_falls_back_with_rest_given_again()
    {
        // TEST-NET-1: never answers, so the connect times out.
        DirectAddress = "192.0.2.1";
        await using var client = await ConnectAsync();

        Assert.StartsWith("350", await client.SendAsync("REST 4"));
        var (data, control) = await client.DownloadAsync("RETR /site/bin/app.dll");

        Assert.Equal("456789", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
        Assert.Equal(0, _direct.Served);
    }

    [Fact]
    public async Task The_client_does_not_see_direct_among_the_features()
    {
        await using var client = await ConnectAsync();

        // Only the feature line: the SITE line may still name DIRECT among the server's commands.
        Assert.DoesNotContain(" DIRECT\r\n", await client.SendAsync("FEAT"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("direct://10.0.0.5,203.0.113.7:50400/0123456789abcdef0123456789abcdef?sha256=" + Fingerprint, 2, 50400)]
    [InlineData("direct://[fe80::1]:443/0123456789abcdef0123456789abcdef?sha256=" + Fingerprint, 1, 443)]
    public void A_direct_address_is_read(string text, int addresses, int port)
    {
        Assert.True(DirectTarget.TryParse(text, out var target));
        Assert.Equal(addresses, target.Addresses.Count);
        Assert.Equal(port, target.Port);
    }

    [Theory]
    [InlineData("ftp://10.0.0.5:21/0123456789abcdef0123456789abcdef?sha256=" + Fingerprint)]
    [InlineData("direct://10.0.0.5/0123456789abcdef0123456789abcdef?sha256=" + Fingerprint)]
    [InlineData("direct://10.0.0.5:50400/not-a-token?sha256=" + Fingerprint)]
    [InlineData("direct://10.0.0.5:50400/0123456789abcdef0123456789abcdef?sha256=abcd")]
    public void A_malformed_direct_address_is_not_used(string text)
    {
        Assert.False(DirectTarget.TryParse(text, out _));
    }

    private const string Fingerprint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    private sealed class DirectFeature : IFtpFeatureProvider
    {
        public IEnumerable<string> GetFeatures(FtpSession session) => session.IsAuthenticated ? ["DIRECT"] : [];
    }

    /// <summary>The server's half: resolves the path as RETR and STOR would and hands out a grant.</summary>
    private sealed class DirectCommand(RelayDirectTests test) : IFtpSiteCommand
    {
        public string Name => "DIRECT";

        public ValueTask ExecuteAsync(FtpSession session, string argument, CancellationToken token)
        {
            var space = argument.IndexOf(' ');

            if (test.RefuseDirect || space < 0 ||
                !SequenceExtensions.TryResolvePath(argument[(space + 1)..], session.CurrentDirectory, out var path))
            {
                return session.WriteAsync("550 Not available directly.\r\n", token);
            }

            var upload = argument[..space].Equals("STOR", StringComparison.OrdinalIgnoreCase);
            var physical = Path.Combine(test._upstream.Root, path.FullName.TrimStart('/'));
            var offset = session.RestartOffset;
            session.RestartOffset = 0;

            var tokenText = test._direct.Grant(physical, upload, offset);
            return session.WriteAsync($"200 direct://{test.DirectAddress}:{test._direct.Port}/{tokenText}?sha256={test._direct.Fingerprint}\r\n", token);
        }
    }

    /// <summary>The machine's half: serves the grants it was given, by the protocol the relay speaks.</summary>
    private sealed class FakeDirectServer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly X509Certificate2 _certificate;
        private readonly ConcurrentDictionary<string, (string Path, bool Upload, long Offset)> _grants = new();
        private readonly CancellationTokenSource _stop = new();
        private int _served;

        public FakeDirectServer()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=direct", key, HashAlgorithmName.SHA256);
            using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            _certificate = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null);
            Fingerprint = Convert.ToHexStringLower(_certificate.GetCertHash(HashAlgorithmName.SHA256));
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public string Fingerprint { get; }

        public int Served => Volatile.Read(ref _served);

        public string Grant(string path, bool upload, long offset)
        {
            var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));
            _grants[token] = (path, upload, offset);
            return token;
        }

        public void Start()
        {
            _listener.Start();
            _ = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;

                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stop.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
                {
                    return;
                }

                _ = ServeAsync(client);
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            await using (var tls = new SslStream(client.GetStream()))
            {
                await tls.AuthenticateAsServerAsync(_certificate);

                var token = await ReadLineAsync(tls);

                if (!_grants.TryRemove(token, out var grant))
                {
                    await WriteAsync(tls, "ERR Unknown token\n");
                    return;
                }

                Interlocked.Increment(ref _served);

                if (!grant.Upload)
                {
                    await using var file = File.OpenRead(grant.Path);
                    file.Seek(grant.Offset, SeekOrigin.Begin);
                    await WriteAsync(tls, $"OK {(file.Length - grant.Offset).ToString(CultureInfo.InvariantCulture)}\n");
                    await file.CopyToAsync(tls);
                    await tls.ShutdownAsync();
                    return;
                }

                await WriteAsync(tls, "OK\n");
                long length = 0;

                await using (var file = File.Create(grant.Path))
                {
                    var header = new byte[4];

                    while (true)
                    {
                        await tls.ReadExactlyAsync(header);
                        var size = (int)BinaryPrimitives.ReadUInt32BigEndian(header);

                        if (size == 0)
                        {
                            break;
                        }

                        var frame = new byte[size];
                        await tls.ReadExactlyAsync(frame);
                        await file.WriteAsync(frame);
                        length += size;
                    }
                }

                await WriteAsync(tls, $"OK {length.ToString(CultureInfo.InvariantCulture)}\n");
            }
        }

        private static async Task<string> ReadLineAsync(Stream stream)
        {
            var line = new StringBuilder();
            var one = new byte[1];

            while (await stream.ReadAsync(one) == 1 && one[0] != '\n')
            {
                line.Append((char)one[0]);
            }

            return line.ToString();
        }

        private static async Task WriteAsync(Stream stream, string text)
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(text));
            await stream.FlushAsync();
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            _certificate.Dispose();
        }
    }
}
