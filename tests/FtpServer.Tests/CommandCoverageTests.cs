using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using FtpServer.Handlers;

namespace FtpServer.Tests;

/// <summary>
/// The commands added to close the gaps a client-compatibility review found: the SITE UTIME forms
/// clients actually send, the timestamp-setting MDTM, MFF and MFCT, MODE Z, SITE SYMLINK and
/// implicit FTPS.
/// </summary>
public class CommandCoverageTests
{
    private static readonly DateTime Expected = new(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);

    private static int FreePort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    // ---- SITE UTIME --------------------------------------------------------

    [Theory]
    [InlineData("SITE UTIME 20200102030405 {0}", "proftpd, time first")]
    [InlineData("SITE UTIME {0} 20200102030405 20200102030405 20200102030405 UTC", "pure-ftpd, three times")]
    [InlineData("SITE UTIME {0} 20200102030405", "path first")]
    public async Task Site_utime_accepts_every_form_clients_send(string command, string form)
    {
        await using var server = await FtpServerFixture.StartAsync();

        // A space in the name, so each form has to find the path boundary properly.
        var file = server.WriteFile("with space.txt", "x");

        await using var client = await server.LoginAsync();
        var reply = await client.SendAsync(string.Format(command, "with space.txt"));

        Assert.True(reply.StartsWith("200", StringComparison.Ordinal), $"{form}: {reply}");
        Assert.Equal(Expected, File.GetLastWriteTimeUtc(file));
    }

    [Fact]
    public async Task Site_utime_accepts_proftpd_minute_precision()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var file = server.WriteFile("minutes.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("SITE UTIME 202001020304 minutes.txt"));
        Assert.Equal(new DateTime(2020, 1, 2, 3, 4, 0, DateTimeKind.Utc), File.GetLastWriteTimeUtc(file));
    }

    [Fact]
    public async Task Site_utime_reports_a_missing_file_and_a_malformed_request_apart()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("550", await client.SendAsync("SITE UTIME 20200102030405 missing.txt"));
        Assert.StartsWith("501", await client.SendAsync("SITE UTIME no time here"));
    }

    // ---- MDTM set form, MFF, MFCT ------------------------------------------

    [Fact]
    public async Task Mdtm_with_a_time_sets_the_modification_time()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var file = server.WriteFile("legacy.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("213", await client.SendAsync("MDTM 20200102030405 legacy.txt"));
        Assert.Equal(Expected, File.GetLastWriteTimeUtc(file));

        // Serv-U's zone suffix: the digits are local time, 60 minutes ahead of UTC.
        Assert.StartsWith("213", await client.SendAsync("MDTM 20200102040405+60 legacy.txt"));
        Assert.Equal(Expected, File.GetLastWriteTimeUtc(file));
    }

    [Fact]
    public async Task Mdtm_still_reads_a_file_whose_name_begins_with_a_timestamp()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var file = server.WriteFile("20200102030405 report.txt", "x");
        File.SetLastWriteTimeUtc(file, new DateTime(2011, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        await using var client = await server.LoginAsync();

        Assert.StartsWith("213 20110101000000", await client.SendAsync("MDTM 20200102030405 report.txt"));
        Assert.Equal(new DateTime(2011, 1, 1, 0, 0, 0, DateTimeKind.Utc), File.GetLastWriteTimeUtc(file));
    }

    [Fact]
    public async Task Mff_sets_the_modify_fact()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var file = server.WriteFile("facts.txt", "x");

        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("MFF modify=20200102030405; facts.txt");

        Assert.StartsWith("213 modify=20200102030405; /facts.txt", reply);
        Assert.Equal(Expected, File.GetLastWriteTimeUtc(file));
    }

    [Fact]
    public async Task Mff_changes_nothing_when_one_fact_cannot_be_set()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var file = server.WriteFile("facts.txt", "x");
        var before = File.GetLastWriteTimeUtc(file);

        await using var client = await server.LoginAsync();

        // draft-somers-ftp-mfxx: all or nothing, and an unchangeable fact is a 504.
        Assert.StartsWith("504", await client.SendAsync("MFF modify=20200102030405;perm=r; facts.txt"));
        Assert.Equal(before, File.GetLastWriteTimeUtc(file));
    }

    [Fact]
    public async Task Mff_sets_the_platform_specific_facts()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var file = server.WriteFile("facts.txt", "x");

        await using var client = await server.LoginAsync();

        if (DefaultFtpCommandHandler.CanSetCreationTime)
        {
            Assert.StartsWith("213", await client.SendAsync("MFF create=20200102030405; facts.txt"));
            Assert.Equal(Expected, File.GetCreationTimeUtc(file));
        }

        if (DefaultFtpCommandHandler.CanSetUnixMode && !OperatingSystem.IsWindows())
        {
            Assert.StartsWith("213", await client.SendAsync("MFF UNIX.mode=0640; facts.txt"));
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead,
                File.GetUnixFileMode(file));
        }
    }

    [Fact]
    public async Task Mfct_sets_the_creation_time_where_the_platform_can()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var file = server.WriteFile("created.txt", "x");

        await using var client = await server.LoginAsync();
        var reply = await client.SendAsync("MFCT 20200102030405 created.txt");

        if (!DefaultFtpCommandHandler.CanSetCreationTime)
        {
            Assert.StartsWith("502", reply);
            return;
        }

        Assert.StartsWith("213 Create=20200102030405; /created.txt", reply);
        Assert.Equal(Expected, File.GetCreationTimeUtc(file));
    }

    [Fact]
    public async Task Feat_lists_the_new_extensions()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        var feat = await client.SendAsync("FEAT");

        Assert.Contains("\r\n MODE Z\r\n", feat, StringComparison.Ordinal);
        Assert.Contains("\r\n MFF modify;", feat, StringComparison.Ordinal);
        Assert.Equal(DefaultFtpCommandHandler.CanSetCreationTime, feat.Contains("\r\n MFCT\r\n", StringComparison.Ordinal));

        // Off by default, so not advertised.
        Assert.DoesNotContain("SYMLINK", feat, StringComparison.Ordinal);
    }

    // ---- MODE Z ------------------------------------------------------------

    [Fact]
    public async Task Mode_z_compresses_downloads_and_listings()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var content = string.Concat(Enumerable.Repeat("compressible line of text\n", 2000));
        server.WriteFile("big.txt", content);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.StartsWith("200", await client.SendAsync("MODE Z"));
        Assert.StartsWith("200", await client.SendAsync("OPTS MODE Z LEVEL 9"));

        var (compressed, control) = await client.DownloadAsync("RETR big.txt");

        Assert.Contains("226", control);
        Assert.True(compressed.Length < content.Length / 10, $"{compressed.Length} bytes for {content.Length}");
        Assert.Equal(content, Encoding.ASCII.GetString(Inflate(compressed)));

        var (listing, _) = await client.DownloadAsync("NLST");
        Assert.Contains("big.txt", Encoding.UTF8.GetString(Inflate(listing)), StringComparison.Ordinal);

        // Back to stream mode, the bytes arrive as they are.
        Assert.StartsWith("200", await client.SendAsync("MODE S"));
        var (plain, _) = await client.DownloadAsync("RETR big.txt");
        Assert.Equal(content, Encoding.ASCII.GetString(plain));
    }

    [Fact]
    public async Task Mode_z_decompresses_uploads()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("MODE Z");

        var payload = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("upload me ", 500)));

        Assert.Contains("226", await client.UploadAsync("STOR up.txt", Deflate(payload)));
        Assert.Equal(payload, await File.ReadAllBytesAsync(Path.Combine(server.Root, "up.txt")));
    }

    [Fact]
    public async Task Mode_z_is_refused_when_disabled_and_reset_by_a_new_login()
    {
        await using (var disabled = await FtpServerFixture.StartAsync(o => o.Features.ModeZ = false))
        {
            await using var client = await disabled.LoginAsync();
            Assert.StartsWith("504", await client.SendAsync("MODE Z"));
        }

        await using var server = await FtpServerFixture.StartAsync();
        await using var session = await server.LoginAsync();

        await session.SendAsync("MODE Z");
        Assert.Contains("transfer MODE: Z", await session.SendAsync("STAT"), StringComparison.Ordinal);

        // RFC 4217 section 4 lists MODE among what a new login starts from scratch.
        await session.SendAsync("USER anonymous");
        await session.SendAsync("PASS a@b.c");
        Assert.Contains("transfer MODE: Stream", await session.SendAsync("STAT"), StringComparison.Ordinal);
    }

    private static byte[] Inflate(byte[] compressed)
    {
        using var input = new ZLibStream(new MemoryStream(compressed), CompressionMode.Decompress);
        using var output = new MemoryStream();
        input.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] Deflate(byte[] plain)
    {
        using var output = new MemoryStream();

        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(plain);
        }

        return output.ToArray();
    }

    // ---- SITE SYMLINK ------------------------------------------------------

    [Fact]
    public async Task Site_symlink_is_off_unless_enabled()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("target.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("504", await client.SendAsync("SITE SYMLINK target.txt link.txt"));
        Assert.False(File.Exists(Path.Combine(server.Root, "link.txt")));
    }

    [Fact]
    public async Task Site_symlink_creates_a_link_inside_the_tree()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Features.SiteSymlink = true);
        server.WriteFile("dir/target.txt", "through the link");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        // Quoted, as Beyond Compare sends it; the target is relative to the link's directory.
        var reply = await client.SendAsync("SITE SYMLINK \"dir/target.txt\" \"the link.txt\"");

        if (OperatingSystem.IsWindows() && reply.StartsWith("550", StringComparison.Ordinal))
        {
            // No symbolic-link privilege (Developer Mode off): nothing more to prove here.
            return;
        }

        Assert.StartsWith("200", reply);

        var (data, _) = await client.DownloadAsync("RETR \"the link.txt\"");
        Assert.Equal("through the link", Encoding.ASCII.GetString(data));

        // The link records a relative path, so it does not pin the server's root location.
        var linkTarget = new FileInfo(Path.Combine(server.Root, "the link.txt")).LinkTarget;
        Assert.False(Path.IsPathRooted(linkTarget), linkTarget);
    }

    [Fact]
    public async Task Site_symlink_cannot_point_outside_the_tree()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Features.SiteSymlink = true);
        await using var client = await server.LoginAsync();

        // ".." is clamped at the root like any pathname, so this names /etc/passwd inside the
        // tree - which does not exist.
        Assert.StartsWith("550", await client.SendAsync("SITE SYMLINK ../../../../etc/passwd escape"));
        Assert.False(File.Exists(Path.Combine(server.Root, "escape")));

        Assert.StartsWith("550", await client.SendAsync("SITE SYMLINK missing.txt link.txt"));
    }

    // ---- implicit FTPS -----------------------------------------------------

    [Fact]
    public async Task Implicit_ftps_protects_the_connection_from_the_first_byte()
    {
        var implicitPort = FreePort();
        await using var server = await FtpServerFixture.StartAsync(o => o.ImplicitTlsPort = implicitPort);
        server.WriteFile("secure.txt", "implicitly protected");

        await using var client = new FtpTestClient(implicitPort, implicitTls: true);
        await client.ConnectAsync();

        Assert.StartsWith("220", client.Banner);

        var feat = await client.SendAsync("FEAT");
        Assert.DoesNotContain("AUTH TLS", feat, StringComparison.Ordinal);
        Assert.Contains("\r\n PROT\r\n", feat, StringComparison.Ordinal);

        Assert.StartsWith("503", await client.SendAsync("AUTH TLS"));
        Assert.StartsWith("230", await LoginAsync(client));
        await client.SendAsync("TYPE I");

        // No PBSZ/PROT sent: the data connection is protected by default.
        Assert.Equal("implicitly protected", await DownloadProtectedAsync(client, "RETR secure.txt"));

        // The plain port is unaffected and still speaks in the clear.
        await using var plain = await server.LoginAsync();
        Assert.StartsWith("257", await plain.SendAsync("PWD"));
    }

    [Fact]
    public async Task Implicit_ftps_keeps_tls_through_rein_and_allows_prot_c()
    {
        var implicitPort = FreePort();
        await using var server = await FtpServerFixture.StartAsync(o => o.ImplicitTlsPort = implicitPort);
        server.WriteFile("clear.txt", "clear data channel");

        await using var client = new FtpTestClient(implicitPort, implicitTls: true);
        await client.ConnectAsync();

        // REIN on an implicit connection must not drop to cleartext: the reply and the commands
        // after it still travel over the same TLS session.
        Assert.StartsWith("220", await client.SendAsync("REIN"));
        Assert.StartsWith("230", await LoginAsync(client));
        await client.SendAsync("TYPE I");

        // PROT without PBSZ is accepted on the implicit port.
        Assert.StartsWith("200", await client.SendAsync("PROT C"));

        var (data, control) = await client.DownloadAsync("RETR clear.txt");
        Assert.Equal("clear data channel", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
    }

    [Fact]
    public void Implicit_ftps_rejects_a_port_that_clashes()
    {
        var options = new Options.FtpOptions { Port = 2121, ImplicitTlsPort = 2121 };

        Assert.False(Options.FtpOptionsValidator.Validate(options, out var error));
        Assert.Contains("ImplicitTlsPort", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Implicit_ftps_works_over_kestrel()
    {
        var implicitPort = FreePort();
        await using var server = await KestrelFixture.StartAsync(o => o.ImplicitTlsPort = implicitPort);

        await using var client = new FtpTestClient(implicitPort, implicitTls: true);
        await client.ConnectAsync();

        Assert.StartsWith("220", client.Banner);
        Assert.StartsWith("230", await LoginAsync(client));
        Assert.Contains("\"/\"", await client.SendAsync("PWD"), StringComparison.Ordinal);
        Assert.StartsWith("503", await client.SendAsync("AUTH TLS"));
    }

    private static async Task<string> LoginAsync(FtpTestClient client)
    {
        await client.SendAsync("USER anonymous");
        return await client.SendAsync("PASS a@b.c");
    }

    private static async Task<string> DownloadProtectedAsync(FtpTestClient client, string command)
    {
        using var data = await client.OpenPassiveAsync();

        await client.SendAsync(command, 0);

        await using var ssl = new SslStream(data.GetStream(), false, static (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "localhost" });

        using var buffer = new MemoryStream();
        await ssl.CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));

        return Encoding.ASCII.GetString(buffer.ToArray());
    }
}
