using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// Covers paths that were implemented but had no test: active mode, ASCII translation, and the
/// less-travelled commands.
/// </summary>
public class ActiveModeTests
{
    [Fact]
    public async Task Active_mode_download_works()
    {
        // The whole PORT path — the server dialling out to the client — had never been exercised;
        // only its rejection cases were covered.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("active.txt", "delivered over an active connection");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var (data, control) = await client.DownloadActiveAsync("RETR active.txt");

        Assert.Equal("delivered over an active connection", Encoding.ASCII.GetString(data));
        Assert.Contains("150", control);
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Active_mode_listing_works()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "x");

        await using var client = await server.LoginAsync();

        var (data, control) = await client.DownloadActiveAsync("LIST");

        Assert.Contains("one.txt", Encoding.UTF8.GetString(data));
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Transfer_without_port_or_pasv_is_refused()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("x.txt", "x");

        await using var client = await server.LoginAsync();

        // No PORT, no PASV: there is nowhere to send the data.
        var reply = await client.SendAsync("RETR x.txt", 1000);

        Assert.Contains("425", reply);
    }
}

public class AsciiModeTests
{
    [Fact]
    public async Task Download_in_ascii_mode_sends_crlf_line_endings()
    {
        // RFC 959 section 3.1.1.1: an ASCII transfer uses CRLF on the wire whatever the host
        // file system stores.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("unix.txt", "alpha\nbeta\ngamma\n");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE A");

        var (data, _) = await client.DownloadAsync("RETR unix.txt");

        Assert.Equal("alpha\r\nbeta\r\ngamma\r\n", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Download_in_ascii_mode_does_not_double_existing_crlf()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("dos.txt", "alpha\r\nbeta\r\n");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE A");

        var (data, _) = await client.DownloadAsync("RETR dos.txt");

        Assert.Equal("alpha\r\nbeta\r\n", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Binary_mode_leaves_line_endings_alone()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("unix.txt", "alpha\nbeta\n");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var (data, _) = await client.DownloadAsync("RETR unix.txt");

        Assert.Equal("alpha\nbeta\n", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Ascii_upload_round_trips_through_the_wire_format()
    {
        // The stored form is host-specific, so the invariant worth asserting is that what comes
        // back out is the same as what went in.
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE A");

        await client.UploadAsync("STOR text.txt", "one\r\ntwo\r\nthree\r\n"u8.ToArray());

        var (data, _) = await client.DownloadAsync("RETR text.txt");

        Assert.Equal("one\r\ntwo\r\nthree\r\n", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Size_reports_the_translated_length_in_ascii_mode()
    {
        // RFC 3659 section 4: SIZE reports the octet count that would be transferred, which is
        // not the length on disk once each bare LF has gained its CR.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("x.txt", "a\nb\n");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE A");

        Assert.Equal("213 6\r\n", await client.SendAsync("SIZE x.txt"));

        // The on-disk length is what IMAGE transfers, and what SIZE reports there.
        await client.SendAsync("TYPE I");

        Assert.Equal("213 4\r\n", await client.SendAsync("SIZE x.txt"));
    }

    [Fact]
    public async Task Restart_is_accepted_in_ascii_mode_but_refused_at_transfer_time()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("x.txt", "0123456789");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE A");

        // Indy's TIdFTP (Beyond Compare) probes resume support with "REST 1" while the session
        // is still in the default TYPE A; a 504 there made it conclude the server cannot resume.
        Assert.StartsWith("350", await client.SendAsync("REST 5"));

        // A marker still in TYPE A when the transfer starts would count translated octets, so it
        // is refused with RFC 959's "invalid REST parameter" - before the 150, not after.
        using var data = await client.OpenPassiveAsync();
        var reply = await client.SendAsync("RETR x.txt", 600);

        Assert.StartsWith("554", reply);
        Assert.DoesNotContain("150", reply);
    }

    [Fact]
    public async Task Restart_set_in_ascii_mode_applies_after_switching_to_image()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("x.txt", "0123456789");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("350", await client.SendAsync("REST 1"));
        Assert.StartsWith("350", await client.SendAsync("REST 0"));
        Assert.StartsWith("350", await client.SendAsync("REST 6"));
        await client.SendAsync("TYPE I");

        var (bytes, control) = await client.DownloadAsync("RETR x.txt");

        Assert.Equal("6789", Encoding.ASCII.GetString(bytes));
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Restart_zero_in_ascii_mode_transfers_normally()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("x.txt", "abc");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE A");

        Assert.StartsWith("350", await client.SendAsync("REST 0"));

        var (bytes, control) = await client.DownloadAsync("RETR x.txt");

        Assert.Equal("abc", Encoding.ASCII.GetString(bytes));
        Assert.Contains("226", control);
    }
}

public class RemainingCommandTests
{
    [Fact]
    public async Task Stou_stores_under_a_generated_name()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var reply = await client.UploadAsync("STOU", "unique"u8.ToArray());

        Assert.Contains("150 FILE:", reply);
        Assert.Contains("226", reply);
        Assert.Single(Directory.GetFiles(server.Root));
        Assert.Equal("unique", File.ReadAllText(Directory.GetFiles(server.Root)[0]));
    }

    [Fact]
    public async Task Rein_returns_the_session_to_its_logged_out_state()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile(Path.Combine("sub", "x.txt"), "x");

        await using var client = await server.LoginAsync();
        await client.SendAsync("CWD sub");

        Assert.StartsWith("220", await client.SendAsync("REIN"));

        // Logged out again.
        Assert.StartsWith("530", await client.SendAsync("PWD"));

        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");

        // And back at the root, not the directory the previous login was in.
        Assert.StartsWith("257 \"/\"", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Xcup_behaves_like_cdup()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile(Path.Combine("sub", "x.txt"), "x");

        await using var client = await server.LoginAsync();
        await client.SendAsync("CWD sub");

        Assert.StartsWith("250", await client.SendAsync("XCUP"));
        Assert.StartsWith("257 \"/\"", await client.SendAsync("XPWD"));
    }

    [Fact]
    public async Task Long_passive_mode_advertises_a_usable_port()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("LPSV");

        // RFC 1639: 228 (af,hal,h1..h4,pal,p1,p2)
        Assert.Matches(@"^228 Entering Long Passive Mode \(4,4,\d+,\d+,\d+,\d+,2,\d+,\d+\)", reply);
    }

    [Fact]
    public async Task Long_port_is_accepted_for_the_control_peer()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("LPRT 4,4,127,0,0,1,2,20,0"));
        Assert.StartsWith("501", await client.SendAsync("LPRT 4,4,8,8,8,8,2,20,0"));
    }

    [Fact]
    public async Task Avbl_and_dsiz_report_numbers()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("a.txt", new string('x', 100));
        server.WriteFile(Path.Combine("sub", "b.txt"), new string('y', 50));

        await using var client = await server.LoginAsync();

        Assert.Matches(@"^213 \d+\r\n$", await client.SendAsync("AVBL"));
        Assert.Equal("213 150\r\n", await client.SendAsync("DSIZ"));
    }

    [Fact]
    public async Task Rmda_removes_a_tree_while_rmd_refuses_a_full_directory()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile(Path.Combine("tree", "nested", "x.txt"), "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("550", await client.SendAsync("RMD tree"));
        Assert.StartsWith("250", await client.SendAsync("RMDA tree"));
        Assert.False(Directory.Exists(Path.Combine(server.Root, "tree")));
    }

    [Fact]
    public async Task Recursive_listing_includes_subdirectory_headers()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("top.txt", "x");
        server.WriteFile(Path.Combine("sub", "inner.txt"), "y");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("LIST -R");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("top.txt", listing);
        Assert.Contains("/sub:", listing);
        Assert.Contains("inner.txt", listing);
    }

    [Fact]
    public async Task Site_utime_sets_the_modification_time()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("stamp.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("SITE UTIME stamp.txt 20200102030405"));
        Assert.Equal("213 20200102030405\r\n", await client.SendAsync("MDTM stamp.txt"));
    }

    [Fact]
    public async Task Site_chmod_reports_honestly_per_platform()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("mode.txt", "x");

        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("SITE CHMOD 640 mode.txt");

        // Windows has no Unix mode bits; by default the 200 says the mode was ignored, so clients
        // that copy permissions on upload do not report every transfer as failed.
        Assert.StartsWith("200", reply);

        if (OperatingSystem.IsWindows())
        {
            Assert.Contains("ignored", reply);
        }
    }

    [Fact]
    public async Task Site_chmod_can_be_strict_where_unsupported()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Features.IgnoreUnsupportedChmod = false);
        server.WriteFile("mode.txt", "x");

        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("SITE CHMOD 640 mode.txt");

        // The option only matters where there are no mode bits to set.
        Assert.StartsWith(OperatingSystem.IsWindows() ? "504" : "200", reply);
    }

    [Fact]
    public async Task Site_chmod_still_validates_its_argument_when_ignored()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync("SITE CHMOD 9z9 mode.txt"));
        Assert.StartsWith("550", await client.SendAsync("SITE CHMOD 644 missing.txt"));
    }

    [Fact]
    public async Task Idle_timeout_closes_the_connection_with_421()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Connection.IdleTimeout = TimeSpan.FromSeconds(2));
        await using var client = await server.ConnectAsync();

        // Comfortably clear of the 2 s timeout, but still tight enough that a reply which is
        // merely late rather than lost would show up as a failure.
        var reply = await client.ReadAsync(10000);

        Assert.StartsWith("421", reply);
    }
}
