using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// Regressions found running the server against Beyond Compare 4, whose FTP support is Indy 10's
/// TIdFTP. Each test pins down what that client sends and the reply it accepts.
/// </summary>
public class BeyondCompareCompatibilityTests
{
    // CRC-32 (IEEE) of "hello world".
    private const string HelloWorldCrc = "0D4A1185";

    // ---- XCRC ---------------------------------------------------------------

    [Fact]
    public async Task Xcrc_answers_250_with_the_bare_digest()
    {
        // TIdFTP accepts only 250 and reads everything after the code as the digest.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("hello.txt", "hello world");

        await using var client = await server.LoginAsync();

        Assert.Equal($"250 {HelloWorldCrc}\r\n", await client.SendAsync("XCRC hello.txt"));
    }

    [Fact]
    public async Task Hash_keeps_its_213_reply()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("hello.txt", "hello world");

        await using var client = await server.LoginAsync();
        await client.SendAsync("OPTS HASH CRC32");

        Assert.StartsWith("213 CRC32 0-10 " + HelloWorldCrc.ToLowerInvariant(), await client.SendAsync("HASH hello.txt"));
    }

    [Theory]
    [InlineData("a,b.txt")]
    [InlineData("report 2023")]
    [InlineData("report 0 5")]
    public async Task Xcrc_reaches_a_file_whose_name_looks_like_a_range(string name)
    {
        // "a,b.txt" was split at the comma, and "report 2023" read 2023 as an end offset.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile(name, "hello world");

        await using var client = await server.LoginAsync();

        Assert.Equal($"250 {HelloWorldCrc}\r\n", await client.SendAsync("XCRC " + name));
    }

    [Fact]
    public async Task Xcrc_still_applies_a_range_to_an_existing_file()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("hello.txt", "hello world");

        await using var client = await server.LoginAsync();

        var whole = await client.SendAsync("XCRC hello.txt");
        var spaced = await client.SendAsync("XCRC hello.txt 0 5");
        var comma = await client.SendAsync("XCRC hello.txt,0,5");

        Assert.Matches(@"^250 [0-9A-F]{8}\r\n$", spaced);
        Assert.NotEqual(whole, spaced);
        Assert.Equal(spaced, comma);
    }

    // ---- REST -----------------------------------------------------------------

    [Fact]
    public async Task Resume_probe_succeeds_in_the_default_type()
    {
        // TIdFTP sends "REST 1" then "REST 0" right after login, before any TYPE command, and
        // treats anything but 350 as "this server cannot resume".
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        Assert.StartsWith("350", await client.SendAsync("REST 1"));
        Assert.StartsWith("350", await client.SendAsync("REST 0"));
    }

    [Fact]
    public async Task Resumed_store_truncates_at_the_end_of_the_new_data()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("resume.txt", "0123456789");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.StartsWith("350", await client.SendAsync("REST 4"));
        Assert.Contains("226", await client.UploadAsync("STOR resume.txt", "AB"u8.ToArray()));

        // Without the truncation the stale "6789" stayed behind the resumed data.
        Assert.Equal("0123AB", await File.ReadAllTextAsync(Path.Combine(server.Root, "resume.txt")));
    }

    [Fact]
    public async Task Resumed_store_past_the_end_is_refused_before_the_150()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("short.txt", "abc");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("REST 100");

        using var data = await client.OpenPassiveAsync();
        var reply = await client.SendAsync("STOR short.txt", 600);

        Assert.StartsWith("554", reply);
        Assert.DoesNotContain("150", reply);
        Assert.Equal("abc", await File.ReadAllTextAsync(Path.Combine(server.Root, "short.txt")));
    }

    [Fact]
    public async Task Resumed_store_of_a_missing_file_is_refused_without_creating_it()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("REST 10");

        using var data = await client.OpenPassiveAsync();
        var reply = await client.SendAsync("STOR new.txt", 600);

        Assert.StartsWith("554", reply);
        Assert.False(File.Exists(Path.Combine(server.Root, "new.txt")));
    }

    [Fact]
    public async Task Restarted_retrieve_past_the_end_is_refused_before_the_150()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("short.txt", "abc");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("REST 100");

        using var data = await client.OpenPassiveAsync();
        var reply = await client.SendAsync("RETR short.txt", 600);

        Assert.StartsWith("554", reply);
        Assert.DoesNotContain("150", reply);
    }

    [Fact]
    public async Task Resumed_store_in_ascii_mode_leaves_the_file_alone()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("text.txt", "0123456789");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE A");
        await client.SendAsync("REST 4");

        using var data = await client.OpenPassiveAsync();
        var reply = await client.SendAsync("STOR text.txt", 600);

        Assert.StartsWith("554", reply);
        Assert.Equal("0123456789", await File.ReadAllTextAsync(Path.Combine(server.Root, "text.txt")));
    }

    // ---- MLSx facts -----------------------------------------------------------

    [Fact]
    public async Task Mlsd_leaves_owner_and_group_out_by_default()
    {
        // TIdFTP never sends OPTS MLST, so the default set is what it gets - and it does not parse
        // UNIX.owner or UNIX.group, the two facts that cost an account lookup.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "hello");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("MLSD");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Matches(@"type=file;size=5;modify=\d{14};perm=[a-z]+;UNIX\.mode=0[0-7]{3}; one\.txt", listing);
        Assert.DoesNotContain("UNIX.owner=", listing);
        Assert.DoesNotContain("UNIX.group=", listing);
    }

    [Fact]
    public async Task Feat_lists_owner_and_group_as_supported_but_not_enabled()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        Assert.Contains(" MLST type*;size*;modify*;perm*;UNIX.mode*;UNIX.owner;UNIX.group;", await client.SendAsync("FEAT"));
    }

    [Fact]
    public async Task Owner_and_group_can_be_opted_into()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "hello");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("OPTS MLST type;UNIX.owner;UNIX.group;"));

        var (data, _) = await client.DownloadAsync("MLSD");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Matches(@"type=file;UNIX\.owner=[^;]+;UNIX\.group=[^;]+; one\.txt", listing);
    }

    [Fact]
    public async Task Perm_withholds_write_access_to_a_read_only_file()
    {
        await using var server = await FtpServerFixture.StartAsync();
        var path = server.WriteFile("locked.txt", "x");
        server.WriteFile("open.txt", "x");

        if (OperatingSystem.IsWindows())
        {
            File.SetAttributes(path, FileAttributes.ReadOnly);
        }
        else
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }

        try
        {
            await using var client = await server.LoginAsync();

            var (data, _) = await client.DownloadAsync("MLSD");
            var listing = Encoding.UTF8.GetString(data);

            Assert.Matches(@"perm=r;[^\r\n]* locked\.txt", listing);
            Assert.Matches(@"perm=rawdf;[^\r\n]* open\.txt", listing);
        }
        finally
        {
            // Otherwise the fixture cannot delete its root on Windows.
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }

    [Fact]
    public async Task Perm_of_a_directory_reflects_the_session()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Authentication.AnonymousCanWrite = false);
        Directory.CreateDirectory(Path.Combine(server.Root, "sub"));

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("MLSD");
        var listing = Encoding.UTF8.GetString(data);

        // A read-only session may enter and list, nothing more.
        Assert.Matches(@"type=dir;[^\r\n]*perm=el;[^\r\n]* sub", listing);
    }

    // ---- SITE CHMOD and LIST -R ------------------------------------------------

    [Fact]
    public async Task Upload_followed_by_chmod_succeeds()
    {
        // "Copy Unix permissions on upload" is on by default in Beyond Compare, so every STOR is
        // followed by a CHMOD; a refusal there is reported as a failed transfer.
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.Contains("226", await client.UploadAsync("STOR up.txt", "data"u8.ToArray()));
        Assert.StartsWith("200", await client.SendAsync("SITE CHMOD 644 up.txt"));
    }

    [Fact]
    public async Task List_recursion_can_be_switched_off()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Features.LISTR = false);
        server.WriteFile("top.txt", "x");
        server.WriteFile("sub/nested.txt", "x");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("LIST -R");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("top.txt", listing);
        Assert.Contains(" sub", listing);
        Assert.DoesNotContain("nested.txt", listing);
    }

    [Fact]
    public async Task List_recursion_is_on_by_default()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("sub/nested.txt", "x");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("LIST -R");

        Assert.Contains("nested.txt", Encoding.UTF8.GetString(data));
    }
}
