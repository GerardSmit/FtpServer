using System.Security.Cryptography;
using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// End-to-end checks against a running server. Each named defect from the review has a test here
/// so it cannot come back unnoticed.
/// </summary>
public class ProtocolIntegrationTests
{
    [Fact]
    public async Task Pipelined_commands_each_get_their_own_reply()
    {
        // Regression: all three used to answer "331", because every line was re-sliced from the
        // start of the read buffer and re-parsed as the first command.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        var reply = await client.SendRawAsync("USER anonymous\r\nPASS a@b.c\r\nPWD\r\n", 600);

        Assert.Contains("331", reply);
        Assert.Contains("230", reply);
        Assert.Contains("257 \"/\"", reply);
    }

    [Fact]
    public async Task Lowercase_verbs_are_accepted()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        Assert.Contains("331", await client.SendAsync("user anonymous"));
        Assert.Contains("230", await client.SendAsync("pass a"));
        Assert.Contains("257", await client.SendAsync("pwd"));
    }

    [Theory]
    [InlineData("PWD")]
    [InlineData("LIST")]
    [InlineData("RETR x")]
    [InlineData("STOR x")]
    [InlineData("MKD x")]
    [InlineData("DELE x")]
    [InlineData("SIZE x")]
    public async Task Filesystem_commands_require_a_login(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        Assert.StartsWith("530", await client.SendAsync(command));
    }

    [Theory]
    [InlineData("FEAT", "211")]
    [InlineData("NOOP", "200")]
    [InlineData("QUIT", "221")]
    [InlineData("HELP", "214")]
    public async Task Some_commands_are_allowed_before_login(string command, string expectedCode)
    {
        // Anchored on the positive reply: asserting only "not 530" would pass on silence.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        Assert.StartsWith(expectedCode, await client.SendAsync(command));
    }

    [Fact]
    public async Task Bad_credentials_are_rejected()
    {
        await using var server = await FtpServerFixture.StartAsync(options =>
        {
            options.Authentication.AllowAnonymous = false;
            options.Authentication.Users.Add(new Options.FtpUserOptions { Name = "bob", Password = "secret" });
        });

        await using var client = await server.ConnectAsync();

        Assert.StartsWith("331", await client.SendAsync("USER bob"));
        Assert.StartsWith("530", await client.SendAsync("PASS wrong"));
        Assert.StartsWith("530", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Good_credentials_are_accepted()
    {
        await using var server = await FtpServerFixture.StartAsync(options =>
        {
            options.Authentication.AllowAnonymous = false;
            options.Authentication.Users.Add(new Options.FtpUserOptions { Name = "bob", Password = "secret" });
        });

        await using var client = await server.ConnectAsync();

        Assert.StartsWith("331", await client.SendAsync("USER bob"));
        Assert.StartsWith("230", await client.SendAsync("PASS secret"));
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Pass_without_user_is_a_sequence_error()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        Assert.StartsWith("503", await client.SendAsync("PASS x"));
    }

    [Theory]
    // Each of these used to throw, send no reply, and leave the session re-throwing forever.
    [InlineData("CWD ..")]
    [InlineData("RETR nope.txt")]
    [InlineData("XCRC nope.txt")]
    [InlineData("EPRT |1|127.0.0.1|99999|")]
    [InlineData("SIZE nope.txt")]
    [InlineData("MDTM nope.txt")]
    public async Task Failing_commands_reply_and_leave_the_session_usable(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync(command);

        Assert.NotEmpty(reply);
        Assert.Matches(@"^[2345]\d\d", reply);

        // The session must still work afterwards.
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Theory]
    [InlineData("PORT 93,184,216,34,0,80")]  // arbitrary internet host
    [InlineData("PORT 127,0,0,1,0,22")]      // localhost SSH
    [InlineData("EPRT |1|8.8.8.8|53|")]
    public async Task Foreign_data_endpoints_are_refused(string command)
    {
        // RFC 2577 section 2: the FTP bounce attack.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync(command));
    }

    [Fact]
    public async Task Privileged_data_ports_are_refused()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        // Own address but a system port.
        Assert.StartsWith("501", await client.SendAsync("PORT 127,0,0,1,0,22"));
    }

    [Fact]
    public async Task Epsv_uses_reply_code_229()
    {
        // RFC 2428 section 3 mandates 229; the code used to send 227.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("229 Entering Extended Passive Mode (|||", await client.SendAsync("EPSV"));
    }

    [Fact]
    public async Task Pasv_reply_is_parenthesised()
    {
        // RFC 959 section 4.1.2 requires the tuple to be wrapped in parentheses.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.Matches(@"^227 Entering Passive Mode \(\d+,\d+,\d+,\d+,\d+,\d+\)\.", await client.SendAsync("PASV"));
    }

    [Fact]
    public async Task Epsv_all_locks_out_other_data_commands()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("EPSV ALL"));
        Assert.StartsWith("501", await client.SendAsync("PORT 127,0,0,1,195,80"));
        Assert.StartsWith("501", await client.SendAsync("PASV"));
    }

    [Fact]
    public async Task Oversized_command_line_is_refused()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync(new string('A', 5000), 500);

        Assert.StartsWith("500", reply);
    }

    [Fact]
    public async Task Empty_command_line_is_a_syntax_error()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("500", await client.SendRawAsync("\r\n"));
    }

    [Fact]
    public async Task Feat_advertises_what_is_implemented()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        await using var client = await server.ConnectAsync();

        var reply = await client.SendAsync("FEAT");

        Assert.StartsWith("211-", reply);
        Assert.EndsWith("211 End\r\n", reply);

        foreach (var feature in new[] { "AUTH TLS", "PBSZ", "PROT", "EPRT", "EPSV", "MDTM", "SIZE", "REST STREAM", "UTF8", "TVFS", "MLST", "MLSD" })
        {
            Assert.Contains("\r\n " + feature, reply);
        }
    }

    [Fact]
    public async Task Retrieving_a_missing_file_does_not_send_150_first()
    {
        // RFC 959: 150 promises a data transfer, so it must not precede an outright failure.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("RETR nope.txt");

        Assert.StartsWith("550", reply);
        Assert.DoesNotContain("150", reply);
    }

    [Fact]
    public async Task Download_is_byte_exact_and_reply_ordering_is_correct()
    {
        await using var server = await FtpServerFixture.StartAsync();

        var payload = RandomNumberGenerator.GetBytes(1024 * 1024);
        File.WriteAllBytes(Path.Combine(server.Root, "blob.bin"), payload);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var (data, control) = await client.DownloadAsync("RETR blob.bin");

        Assert.Equal(payload, data);
        Assert.Contains("150", control);
        Assert.Contains("226", control);
        Assert.True(control.IndexOf("150", StringComparison.Ordinal) < control.IndexOf("226", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Upload_then_download_round_trips()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var payload = Encoding.ASCII.GetBytes("uploaded content");

        Assert.Contains("226", await client.UploadAsync("STOR up.txt", payload));
        Assert.Equal("uploaded content", File.ReadAllText(Path.Combine(server.Root, "up.txt")));

        var (data, _) = await client.DownloadAsync("RETR up.txt");
        Assert.Equal(payload, data);
    }

    [Fact]
    public async Task Rest_resumes_at_the_requested_offset()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("resume.txt", "0123456789");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.StartsWith("350", await client.SendAsync("REST 4"));

        var (data, _) = await client.DownloadAsync("RETR resume.txt");
        Assert.Equal("456789", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Append_extends_an_existing_file()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("append.txt", "start");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.Contains("226", await client.UploadAsync("APPE append.txt", "-more"u8.ToArray()));
        Assert.Equal("start-more", File.ReadAllText(Path.Combine(server.Root, "append.txt")));
    }

    [Fact]
    public async Task Directory_lifecycle_works()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("257 \"/newdir\"", await client.SendAsync("MKD newdir"));
        Assert.True(Directory.Exists(Path.Combine(server.Root, "newdir")));

        Assert.StartsWith("250", await client.SendAsync("CWD newdir"));
        Assert.StartsWith("257 \"/newdir\"", await client.SendAsync("PWD"));
        Assert.StartsWith("250", await client.SendAsync("CDUP"));

        Assert.StartsWith("250", await client.SendAsync("RMD newdir"));
        Assert.False(Directory.Exists(Path.Combine(server.Root, "newdir")));
    }

    [Fact]
    public async Task Rename_requires_rnfr_then_rnto()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("old.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("503", await client.SendAsync("RNTO new.txt"));
        Assert.StartsWith("350", await client.SendAsync("RNFR old.txt"));
        Assert.StartsWith("250", await client.SendAsync("RNTO new.txt"));

        Assert.True(File.Exists(Path.Combine(server.Root, "new.txt")));
        Assert.False(File.Exists(Path.Combine(server.Root, "old.txt")));
    }

    [Fact]
    public async Task Delete_removes_a_file()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("gone.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("250", await client.SendAsync("DELE gone.txt"));
        Assert.False(File.Exists(Path.Combine(server.Root, "gone.txt")));
    }

    [Fact]
    public async Task Read_only_mode_refuses_every_mutation()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.ReadOnly = true);
        server.WriteFile("file.txt", "x");

        await using var client = await server.LoginAsync();

        foreach (var command in new[] { "MKD d", "RMD d", "DELE file.txt", "RNFR file.txt" })
        {
            Assert.StartsWith("550", await client.SendAsync(command));
        }

        // Reading still works.
        Assert.StartsWith("213", await client.SendAsync("SIZE file.txt"));
    }

    [Fact]
    public async Task List_honours_its_pathname_argument()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("top.txt", "x");
        server.WriteFile(Path.Combine("sub", "inner.txt"), "y");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("LIST sub");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("inner.txt", listing);
        Assert.DoesNotContain("top.txt", listing);
    }

    [Fact]
    public async Task List_ignores_ls_flags_but_keeps_the_path()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("top.txt", "x");
        server.WriteFile(Path.Combine("sub", "inner.txt"), "y");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("LIST -al sub");

        Assert.Contains("inner.txt", Encoding.UTF8.GetString(data));
    }

    [Fact]
    public async Task Nlst_returns_bare_names()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "x");

        await using var client = await server.LoginAsync();

        var (data, control) = await client.DownloadAsync("NLST");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("226", control);
        Assert.Equal("one.txt", listing.Trim());
    }

    [Fact]
    public async Task Mlsd_emits_facts_and_the_cdir_entry()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "hello");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("MLSD");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("type=cdir;", listing);
        Assert.Contains("type=file;size=5;", listing);
        Assert.Contains("perm=", listing);
    }

    [Fact]
    public async Task Mlst_replies_on_the_control_connection()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "hello");

        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("MLST one.txt");

        Assert.StartsWith("250-", reply);
        Assert.Contains("\r\n type=file;size=5;", reply);
        Assert.EndsWith("250 End\r\n", reply);
    }

    [Fact]
    public async Task Long_listing_has_a_link_count_and_a_real_size()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("sized.txt", new string('x', 42));

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("LIST");
        var line = Encoding.UTF8.GetString(data).Split("\r\n").First(l => l.Contains("sized.txt"));

        // <perms> <links> <owner> <group> <size> <date> <name>
        Assert.Matches(@"^[-d][rwx-]{9} [1-9]\d* \S+ \S+ 42 \w{3} \d{2} [\d: ]{5} sized\.txt$", line);
    }

    [Fact]
    public async Task Size_and_mdtm_report_metadata()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var path = server.WriteFile("meta.txt", "0123456789");
        File.SetLastWriteTimeUtc(path, new DateTime(2019, 3, 4, 11, 22, 33, DateTimeKind.Utc));

        await using var client = await server.LoginAsync();

        Assert.Equal("213 10\r\n", await client.SendAsync("SIZE meta.txt"));
        Assert.Equal("213 20190304112233\r\n", await client.SendAsync("MDTM meta.txt"));
    }

    [Fact]
    public async Task Mfmt_sets_the_modification_time()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("touch.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("213 Modify=", await client.SendAsync("MFMT 20200102030405 touch.txt"));
        Assert.Equal("213 20200102030405\r\n", await client.SendAsync("MDTM touch.txt"));
    }

    [Fact]
    public async Task Checksums_match_the_reference_implementations()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("hash.txt", "hello world");

        await using var client = await server.LoginAsync();

        var expectedSha256 = Convert.ToHexString(SHA256.HashData("hello world"u8.ToArray()));
        var expectedMd5 = Convert.ToHexString(MD5.HashData("hello world"u8.ToArray()));

        Assert.Equal($"213 {expectedSha256}\r\n", await client.SendAsync("XSHA256 hash.txt"));
        Assert.Equal($"213 {expectedMd5}\r\n", await client.SendAsync("XMD5 hash.txt"));

        // draft-bryan-ftp-range uses an inclusive end offset, so 11 octets report as 0-10, and
        // the hash draft asks for a lowercase digest.
        Assert.Contains($"SHA-256 0-10 {expectedSha256.ToLowerInvariant()}", await client.SendAsync("HASH hash.txt"));
    }

    [Fact]
    public async Task Checksum_range_is_applied()
    {
        // The end offset used to be parsed and then ignored, so a range returned the whole-file
        // checksum.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("range.txt", "hello world");

        await using var client = await server.LoginAsync();

        var whole = await client.SendAsync("XSHA256 range.txt");
        var part = await client.SendAsync("XSHA256 range.txt,0,5");

        Assert.NotEqual(whole, part);
        Assert.Equal($"213 {Convert.ToHexString(SHA256.HashData("hello"u8.ToArray()))}\r\n", part);
    }

    [Fact]
    public async Task Utf8_filenames_survive_a_round_trip()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("café-日本.txt", "unicode");

        await using var client = await server.LoginAsync();
        await client.SendAsync("OPTS UTF8 ON");

        var (data, _) = await client.DownloadAsync("NLST");
        Assert.Contains("café-日本.txt", Encoding.UTF8.GetString(data));

        Assert.Equal("213 7\r\n", await client.SendAsync("SIZE café-日本.txt"));
    }

    [Fact]
    public async Task Nothing_outside_the_root_is_reachable()
    {
        await using var server = await FtpServerFixture.StartAsync();

        var outside = Path.Combine(Path.GetDirectoryName(server.Root)!, "outside-secret.txt");
        File.WriteAllText(outside, "TOP SECRET");

        try
        {
            await using var client = await server.LoginAsync();

            // Every one of these forms used to either escape or wedge the session.
            Assert.StartsWith("250", await client.SendAsync("CWD /../"));
            Assert.StartsWith("257 \"/\"", await client.SendAsync("PWD"));
            Assert.StartsWith("550", await client.SendAsync("RETR /../outside-secret.txt"));
            Assert.StartsWith("550", await client.SendAsync("RETR ../outside-secret.txt"));
            Assert.StartsWith("550", await client.SendAsync("CWD /mnt/c"));
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Fact]
    public async Task Abor_with_no_transfer_running_is_acknowledged()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("226", await client.SendAsync("ABOR"));
    }

    [Fact]
    public async Task Abor_interrupts_a_transfer_in_progress()
    {
        // The control connection used not to be read at all during a transfer, so an ABOR could
        // not be received until the transfer had already finished.
        await using var server = await FtpServerFixture.StartAsync();

        File.WriteAllBytes(Path.Combine(server.Root, "huge.bin"), new byte[64 * 1024 * 1024]);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();

        // Start the download but read only a little, so it cannot complete on its own.
        await client.SendAsync("RETR huge.bin", 0);
        await Task.Delay(150);

        // Drain a little so the transfer is genuinely in flight, but nowhere near completion.
        var sink = new byte[4096];
        var drained = await data.GetStream().ReadAsync(sink).AsTask().WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(drained > 0);

        // Nothing should have been sent on the control channel yet; a 426 arriving here would
        // mean the transfer died on its own and the ABOR assertions below would prove nothing.
        Assert.Equal(string.Empty, await client.ReadAsync(200));

        var reply = await client.SendAsync("ABOR", 1000);

        // 426 closes out the transfer, 226 acknowledges the ABOR itself (RFC 959 section 4.1.3).
        Assert.Contains("426", reply);
        Assert.Contains("226", reply);

        data.Close();

        // The control connection survives the abort.
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Quit_closes_the_connection()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("221", await client.SendAsync("QUIT"));

        // IsClosedAsync distinguishes end-of-stream from a quiet connection; asserting an empty
        // read could not, and flaked whenever the 221 straddled the settle window.
        Assert.True(await client.IsClosedAsync(), "the server replied 221 but left the connection open");
    }

    [Fact]
    public async Task Connection_limit_is_enforced()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Connection.MaxConnections = 2;
            o.Connection.MaxConnectionsPerAddress = 2;
        });

        await using var first = await server.ConnectAsync();
        await using var second = await server.ConnectAsync();
        await using var third = new FtpTestClient(server.Port);

        await third.ConnectAsync();

        Assert.StartsWith("421", third.Banner);
    }

    [Fact]
    public async Task Ftps_upgrades_the_control_connection()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        await using var client = await server.ConnectAsync();

        Assert.StartsWith("234", await client.SendAsync("AUTH TLS"));

        await client.StartTlsAsync();

        Assert.StartsWith("200 PBSZ=0", await client.SendAsync("PBSZ 0"));
        Assert.StartsWith("200", await client.SendAsync("PROT P"));
        Assert.StartsWith("331", await client.SendAsync("USER anonymous"));
        Assert.StartsWith("230", await client.SendAsync("PASS a@b.c"));
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Auth_with_an_unknown_mechanism_is_refused()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        await using var client = await server.ConnectAsync();

        Assert.StartsWith("504", await client.SendAsync("AUTH GSSAPI"));

        // The session is still usable and can still upgrade.
        Assert.StartsWith("234", await client.SendAsync("AUTH TLS"));
    }

    [Fact]
    public async Task Prot_requires_pbsz_first()
    {
        // RFC 2228 section 3 sequencing.
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        await using var client = await server.ConnectAsync();

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();

        Assert.StartsWith("503", await client.SendAsync("PROT P"));
        Assert.StartsWith("200", await client.SendAsync("PBSZ 0"));

        // RFC 2228 assigns 536 to "requested PROT level not supported by mechanism"; 521 is not
        // in its reply set at all.
        Assert.StartsWith("536", await client.SendAsync("PROT S"));
        Assert.StartsWith("536", await client.SendAsync("PROT E"));
        Assert.StartsWith("200", await client.SendAsync("PROT C"));
    }

    [Fact]
    public async Task Data_connection_can_be_protected_with_tls()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        server.WriteFile("secure.txt", "encrypted payload");

        await using var client = await server.ConnectAsync();

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("PBSZ 0");
        await client.SendAsync("PROT P");
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();

        await client.SendAsync("RETR secure.txt", 0);

        await using var ssl = new System.Net.Security.SslStream(data.GetStream(), false, static (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = "localhost" });

        using var buffer = new MemoryStream();
        await ssl.CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Equal("encrypted payload", Encoding.ASCII.GetString(buffer.ToArray()));
    }
}
