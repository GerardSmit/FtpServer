using System.Globalization;
using System.Text;
using FluentFTP;
using FluentFTP.Exceptions;
using FtpServer.Options;
using FtpServer.Relay;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer.Tests;

/// <summary>
/// The relay end to end: plain FTP clients against the relay, which relays every connection to a
/// real FTPS server that refuses anything but TLS.
/// </summary>
public sealed class RelayTests : IAsyncLifetime
{
    private const string User = "jan";
    private const string Password = "relay-secret";

    private FtpServerFixture _upstream = null!;
    private readonly List<IHost> _relays = [];

    public async ValueTask InitializeAsync()
    {
        _upstream = await FtpServerFixture.StartAsync(o =>
        {
            o.Ftps = true;
            o.RequireTls = true;
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new FtpUserOptions { Name = User, Password = Password });
            o.List.TimeZone = "UTC";
        });

        _upstream.WriteFile("site/default.aspx", "hello");
        _upstream.WriteFile("site/bin/app.dll", "0123456789");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var relay in _relays)
        {
            await relay.StopAsync();
            relay.Dispose();
        }

        await _upstream.DisposeAsync();
    }

    private async Task<int> StartRelayAsync(bool offerMlsd = false, int? upstreamPort = null, string upstreamHost = "localhost")
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
            OfferMlsd = offerMlsd,
            Upstream = new UpstreamOptions
            {
                Host = upstreamHost,
                Port = upstreamPort ?? _upstream.Port,
                CertificateThumbprint = thumbprint,
                TimeoutSeconds = 15
            }
        });

        var relay = builder.Build();
        await relay.StartAsync();
        _relays.Add(relay);

        var server = relay.Services.GetRequiredService<RelayServer>();
        await server.Listening;
        return server.Port;
    }

    private static async Task<AsyncFtpClient> ConnectAsync(int port, string password = Password)
    {
        var client = new AsyncFtpClient("127.0.0.1", User, password, port);
        client.Config.EncryptionMode = FtpEncryptionMode.None;
        client.Config.DataConnectionType = FtpDataConnectionType.PASV;
        client.Config.ConnectTimeout = 15_000;
        client.Config.ReadTimeout = 15_000;
        await client.Connect();
        return client;
    }

    private static async Task<FtpTestClient> RawAsync(int port)
    {
        var client = new FtpTestClient(port);
        await client.ConnectAsync();
        await client.SendAsync($"USER {User}");
        Assert.StartsWith("230", await client.SendAsync($"PASS {Password}"));
        return client;
    }

    private string Upstream(string relative) => Path.Combine(_upstream.Root, relative);

    // FluentFTP reads MLSD, so these run against a relay that offers it.

    [Fact]
    public async Task A_plain_login_reaches_the_tls_only_server_and_lists_its_tree()
    {
        await using var client = await ConnectAsync(await StartRelayAsync(offerMlsd: true));

        var root = await client.GetListing("/");
        var site = await client.GetListing("/site");

        Assert.Equal(["site"], root.Select(x => x.Name));
        Assert.Equal(["bin", "default.aspx"], site.Select(x => x.Name).Order());
        Assert.Equal(5, site.Single(x => x.Name == "default.aspx").Size);
    }

    [Fact]
    public async Task A_wrong_password_is_refused_as_the_server_refuses_it()
    {
        var port = await StartRelayAsync(offerMlsd: true);

        await Assert.ThrowsAnyAsync<FtpException>(() => ConnectAsync(port, password: "wrong"));
    }

    [Fact]
    public async Task A_download_and_a_resumed_download_come_from_the_server()
    {
        await using var client = await ConnectAsync(await StartRelayAsync(offerMlsd: true));

        Assert.Equal("0123456789", Encoding.ASCII.GetString(await client.DownloadBytes("/site/bin/app.dll", CancellationToken.None)));

        await using (var resumed = await client.OpenRead("/site/bin/app.dll", FtpDataType.Binary, restart: 4, checkIfFileExists: false))
        using (var reader = new StreamReader(resumed))
        {
            Assert.Equal("456789", await reader.ReadToEndAsync());
        }

        await client.GetReply();
    }

    [Fact]
    public async Task Uploads_land_on_the_server()
    {
        await using var client = await ConnectAsync(await StartRelayAsync(offerMlsd: true));

        Assert.Equal(FtpStatus.Success, await client.UploadBytes("new"u8.ToArray(), "/site/new.txt"));
        Assert.Equal(FtpStatus.Success, await client.UploadBytes("bye"u8.ToArray(), "/site/default.aspx", FtpRemoteExists.Overwrite));
        Assert.Equal(FtpStatus.Success, await client.UploadBytes([], "/site/empty.txt"));

        Assert.Equal("new", File.ReadAllText(Upstream("site/new.txt")));
        Assert.Equal("bye", File.ReadAllText(Upstream("site/default.aspx")));
        Assert.Equal(0, new FileInfo(Upstream("site/empty.txt")).Length);
    }

    [Fact]
    public async Task Directories_renames_and_deletes_are_made_on_the_server()
    {
        await using var client = await ConnectAsync(await StartRelayAsync(offerMlsd: true));

        await client.CreateDirectory("/site/App_Data", force: false);
        await client.Rename("/site/default.aspx", "/site/index.aspx");
        await client.DeleteFile("/site/bin/app.dll");

        Assert.True(Directory.Exists(Upstream("site/App_Data")));
        Assert.True(File.Exists(Upstream("site/index.aspx")));
        Assert.False(File.Exists(Upstream("site/bin/app.dll")));

        await client.DeleteDirectory("/site/App_Data");
        Assert.False(Directory.Exists(Upstream("site/App_Data")));
    }

    [Fact]
    public async Task Commands_and_replies_pass_as_they_are()
    {
        await using var client = await RawAsync(await StartRelayAsync());

        Assert.Equal("250 A684C7C6", (await client.SendAsync("XCRC /site/bin/app.dll")).Trim());
        Assert.StartsWith("550", await client.SendAsync("CWD /missing"));
        Assert.StartsWith("213 10", await client.SendAsync("SIZE /site/bin/app.dll"));
    }

    // What the relay changes.

    [Fact]
    public async Task Features_leave_out_tls_and_mlsd_unless_offered()
    {
        await using var client = await RawAsync(await StartRelayAsync());

        var features = await client.SendAsync("FEAT");

        Assert.Contains(" XCRC", features, StringComparison.Ordinal);
        Assert.DoesNotContain(" MLSD", features, StringComparison.Ordinal);
        Assert.DoesNotContain(" AUTH", features, StringComparison.Ordinal);
        Assert.StartsWith("502", await client.SendAsync("MLSD /"));
        Assert.StartsWith("502", await client.SendAsync("AUTH TLS"));
    }

    [Fact]
    public async Task A_recursive_list_has_every_time_to_the_second_in_the_clients_zone()
    {
        await using var client = await RawAsync(await StartRelayAsync());

        var (data, control) = await client.DownloadAsync("LIST -R /site");
        var text = Encoding.UTF8.GetString(data);

        // The server writes UTC; the client gets this machine's zone without daylight saving time.
        var written = (File.GetLastWriteTimeUtc(Upstream("site/bin/app.dll")) + TimeZoneInfo.Local.BaseUtcOffset)
            .ToString("MMM dd HH:mm:ss yyyy", CultureInfo.InvariantCulture);

        Assert.Contains("226", control);
        Assert.Contains("/site/bin:", text, StringComparison.Ordinal);
        Assert.Contains($" 10 {written} app.dll", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_server_reached_over_ipv4_takes_the_data_connection_too()
    {
        // The control socket reports an IPv4 server as ::ffff:127.0.0.1, which a data socket must not dial as such.
        await using var client = await RawAsync(await StartRelayAsync(upstreamHost: "127.0.0.1"));

        var (data, control) = await client.DownloadAsync("RETR /site/bin/app.dll");

        Assert.Equal("0123456789", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Active_mode_reaches_the_client()
    {
        await using var client = await RawAsync(await StartRelayAsync());

        var (data, control) = await client.DownloadActiveAsync("RETR /site/bin/app.dll");

        Assert.Equal("0123456789", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Abor_stops_a_transfer_on_both_sides_and_the_session_goes_on()
    {
        File.WriteAllBytes(Upstream("site/big.bin"), new byte[64 * 1024 * 1024]);

        await using var client = await RawAsync(await StartRelayAsync());
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();
        var started = await client.SendAsync("RETR /site/big.bin", settleMs: 500);
        Assert.StartsWith("150", started);

        var buffer = new byte[64 * 1024];
        await data.GetStream().ReadAtLeastAsync(buffer, buffer.Length);

        var aborted = await client.SendAsync("ABOR", settleMs: 1000);
        Assert.Contains("226", aborted);

        Assert.StartsWith("200", await client.SendAsync("NOOP"));
    }

    [Fact]
    public async Task A_server_that_cannot_be_reached_is_said_at_once()
    {
        var (unused, _, _) = FtpServerFixture.ReservePorts();
        var port = await StartRelayAsync(upstreamPort: unused);

        await using var client = new FtpTestClient(port);
        await client.ConnectAsync();

        Assert.StartsWith("421", client.Banner);
    }

    // The rewrites on their own.

    [Theory]
    [InlineData("", "LIST -T")]
    [InlineData("/site", "LIST -T /site")]
    [InlineData("-R", "LIST -RT")]
    [InlineData("-al /site", "LIST -alT /site")]
    [InlineData("-RT /site", "LIST -RT /site")]
    public void List_gets_complete_times(string argument, string expected)
    {
        Assert.Equal(expected, Rewrites.ListWithCompleteTimes(argument));
    }

    [Fact]
    public void Only_the_time_of_a_listing_line_changes()
    {
        var plus2 = TimeZoneInfo.CreateCustomTimeZone("plus2", TimeSpan.FromHours(2), "plus2", "plus2");

        var line = Encoding.UTF8.GetBytes("-rw-r--r-- 1 ftp ftp 525 Dec 31 23:30:05 2025 web  config.txt\r\n");
        var converted = Encoding.UTF8.GetString(Rewrites.Convert(line, TimeZoneInfo.Utc, plus2));

        Assert.Equal("-rw-r--r-- 1 ftp ftp 525 Jan 01 01:30:05 2026 web  config.txt\r\n", converted);

        // A header, or a time without seconds, passes as it came.
        foreach (var other in new[] { "/site/bin:\r\n", "-rw-r--r-- 1 ftp ftp 525 Dec 31 23:30 web.config\r\n" })
        {
            Assert.Equal(other, Encoding.UTF8.GetString(Rewrites.Convert(Encoding.UTF8.GetBytes(other), TimeZoneInfo.Utc, plus2)));
        }
    }
}
