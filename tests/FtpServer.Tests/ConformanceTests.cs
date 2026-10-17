using System.Security.Cryptography;
using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// Conformance points raised by the second review round, each pinned to the RFC that decides it.
/// </summary>
public class ConformanceTests
{
    [Fact]
    public async Task Feat_advertises_host_and_rang()
    {
        // RFC 7151 section 3.1 requires a server implementing HOST to advertise it; clients probe
        // FEAT first and will otherwise never send the command.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        var reply = await client.SendAsync("FEAT");

        Assert.Contains("\r\n HOST", reply);
        Assert.Contains("\r\n AVBL", reply);
        Assert.Contains("\r\n DSIZ", reply);
        Assert.Contains("\r\n RMDA", reply);
        Assert.Contains("\r\n CSID", reply);
    }

    [Fact]
    public async Task Feat_only_advertises_passive_commands_when_passive_is_enabled()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Passive = false);
        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("FEAT");

        Assert.DoesNotContain("\r\n EPSV", reply);
        Assert.DoesNotContain("\r\n PASV", reply);
        Assert.StartsWith("502", await client.SendAsync("PASV"));
    }

    [Fact]
    public async Task Rang_end_offset_is_inclusive()
    {
        // draft-bryan-ftp-range: "RANG 0 4" selects five octets.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("rang.txt", "hello world");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("350", await client.SendAsync("RANG 0 4"));

        // HASH digests are lowercase per draft-bryan-ftpext-hash section 3.
        var expected = Convert.ToHexStringLower(SHA256.HashData("hello"u8.ToArray()));
        Assert.Contains($"SHA-256 0-4 {expected}", await client.SendAsync("HASH rang.txt"));
    }

    [Fact]
    public async Task Rang_with_start_after_end_resets_the_range()
    {
        // The draft's documented reset form is "RANG 1 0", which must answer 350, not 501.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("rang.txt", "hello world");

        await using var client = await server.LoginAsync();

        await client.SendAsync("RANG 0 4");
        Assert.StartsWith("350", await client.SendAsync("RANG 1 0"));

        // With the range cleared the whole file is digested again.
        var whole = Convert.ToHexStringLower(SHA256.HashData("hello world"u8.ToArray()));
        Assert.Contains($"SHA-256 0-10 {whole}", await client.SendAsync("HASH rang.txt"));
    }

    [Fact]
    public async Task Rang_applies_to_only_one_command()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("rang.txt", "hello world");

        await using var client = await server.LoginAsync();
        await client.SendAsync("RANG 0 4");

        var ranged = await client.SendAsync("HASH rang.txt");
        var subsequent = await client.SendAsync("HASH rang.txt");

        Assert.Contains("0-4", ranged);
        Assert.Contains("0-10", subsequent);
    }

    [Fact]
    public async Task Hash_treats_its_whole_argument_as_a_pathname()
    {
        // The X* commands accept a trailing range; HASH does not, so a name ending in digits must
        // not be chopped up.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("Track 01", "content");

        await using var client = await server.LoginAsync();

        var expected = Convert.ToHexStringLower(SHA256.HashData("content"u8.ToArray()));
        Assert.Contains(expected, await client.SendAsync("HASH Track 01"));
    }

    [Fact]
    public async Task Opts_mlst_narrows_the_facts_that_mlsd_emits()
    {
        // RFC 3659 section 7.9: after OPTS MLST the server emits only the requested facts.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "hello");

        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("OPTS MLST type;size;");

        Assert.StartsWith("200 MLST OPTS type;size;", reply);

        var (data, _) = await client.DownloadAsync("MLSD");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("type=file;size=5; one.txt", listing);
        Assert.DoesNotContain("perm=", listing);
        Assert.DoesNotContain("UNIX.mode=", listing);
    }

    [Fact]
    public async Task Mlst_reports_the_requested_pathname()
    {
        // RFC 3659 section 7.3.1: with TVFS advertised the entry carries the requested path.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile(Path.Combine("pub", "readme.txt"), "x");

        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("MLST /pub/readme.txt");

        Assert.Contains(" /pub/readme.txt\r\n", reply);
    }

    [Fact]
    public async Task Xcwd_is_a_synonym_for_cwd()
    {
        // RFC 1123 section 4.1.3.1 asks for the RFC 775 verbs to be accepted.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile(Path.Combine("sub", "x.txt"), "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("250", await client.SendAsync("XCWD sub"));
        Assert.StartsWith("257 \"/sub\"", await client.SendAsync("XPWD"));
    }

    [Fact]
    public async Task Stat_uses_212_for_a_directory_and_213_for_a_file()
    {
        // RFC 959 section 4.2.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("212", await client.SendAsync("STAT /"));
        Assert.StartsWith("213", await client.SendAsync("STAT one.txt"));
    }

    [Fact]
    public async Task Machine_listings_never_carry_a_truncation_notice()
    {
        // RFC 3659 section 7.2 forbids extra lines in MLSD; in NLST the notice would parse as
        // several bogus filenames.
        await using var server = await FtpServerFixture.StartAsync(o => o.List.MaxEntries = 3);

        for (var i = 0; i < 10; i++)
        {
            server.WriteFile($"file{i}.txt", "x");
        }

        await using var client = await server.LoginAsync();

        var (mlsd, _) = await client.DownloadAsync("MLSD");
        Assert.DoesNotContain("truncated", Encoding.UTF8.GetString(mlsd));

        var (nlst, _) = await client.DownloadAsync("NLST");
        Assert.DoesNotContain("truncated", Encoding.UTF8.GetString(nlst));

        // The human-readable listing may still say so.
        var (list, _) = await client.DownloadAsync("LIST");
        Assert.Contains("truncated", Encoding.UTF8.GetString(list));
    }

    [Theory]
    [InlineData("TYPE Ix")]
    [InlineData("TYPE I 9")]
    [InlineData("TYPE A Q")]
    [InlineData("TYPE L 7")]
    public async Task Malformed_type_arguments_are_refused(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync(command);

        Assert.Matches(@"^(501|504)", reply);
    }

    [Theory]
    [InlineData("TYPE I")]
    [InlineData("TYPE A")]
    [InlineData("TYPE A N")]
    [InlineData("TYPE L 8")]
    public async Task Valid_type_arguments_are_accepted(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync(command));
    }

    [Fact]
    public async Task Epsv_all_also_locks_out_the_long_and_extended_forms()
    {
        // RFC 2428 section 4 latches the session, and the latch must cover every data-port command.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("EPSV ALL"));

        foreach (var command in new[] { "PORT 127,0,0,1,195,80", "EPRT |1|127.0.0.1|50000|", "LPRT 4,4,127,0,0,1,2,195,80", "PASV", "LPSV" })
        {
            Assert.StartsWith("501", await client.SendAsync(command));
        }
    }

    [Fact]
    public async Task Epsv_all_survives_a_second_login()
    {
        // "for the remainder of the session", so a second USER must not clear the latch.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        await client.SendAsync("EPSV ALL");
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");

        Assert.StartsWith("501", await client.SendAsync("PASV"));
    }

    [Fact]
    public async Task Reinitialize_clears_the_epsv_all_latch()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        await client.SendAsync("EPSV ALL");
        Assert.StartsWith("220", await client.SendAsync("REIN"));

        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");

        Assert.StartsWith("227", await client.SendAsync("PASV"));
    }

    [Fact]
    public async Task Session_state_commands_require_a_login()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        foreach (var command in new[] { "TYPE A", "MODE S", "STRU F", "ALLO 100", "ABOR", "RANG 0 1", "REST 5" })
        {
            Assert.StartsWith("530", await client.SendAsync(command));
        }
    }

    [Fact]
    public async Task Lockout_closes_the_control_connection()
    {
        // 421 means "closing control connection", so it has to actually close.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.MaxFailedAttempts = 1;
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "bob", Password = "secret" });
        });

        await using var client = await server.ConnectAsync();

        await client.SendAsync("USER bob");
        Assert.StartsWith("530", await client.SendAsync("PASS wrong"));
        Assert.StartsWith("421", await client.SendAsync("USER bob"));

        Assert.True(await client.IsClosedAsync(), "the server sent 421 but left the connection open");
    }

    [Fact]
    public async Task A_configured_user_is_not_shadowed_by_anonymous_access()
    {
        // With anonymous enabled, a real account called "ftp" must still need its password.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = true;
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "ftp", Password = "secret" });
        });

        await using var client = await server.ConnectAsync();

        await client.SendAsync("USER ftp");
        Assert.StartsWith("530", await client.SendAsync("PASS not-the-password"));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("../../..")]
    [InlineData("../outside")]
    public async Task A_home_directory_cannot_widen_a_user(string home)
    {
        // A per-user home narrows a user; an absolute or escaping value must not mount the host.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new Options.FtpUserOptions
            {
                Name = "bob",
                Password = "secret",
                HomeDirectory = home,
            });
        });

        server.WriteFile("inside.txt", "in the root");

        await using var client = await server.ConnectAsync();
        await client.SendAsync("USER bob");
        Assert.StartsWith("230", await client.SendAsync("PASS secret"));

        // Falls back to the server root rather than anything above it.
        var (data, _) = await client.DownloadAsync("NLST");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("inside.txt", listing);
        Assert.DoesNotContain("Windows", listing);
        Assert.DoesNotContain("etc", listing);
    }

    [Theory]
    [InlineData("Port", 0)]
    [InlineData("MaxCommandLength", 8)]
    [InlineData("PassiveOverlapsControl", 0)]
    public async Task Invalid_configuration_is_refused_at_startup(string scenario, int value)
    {
        var failed = false;

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                switch (scenario)
                {
                    case "Port":
                        o.Port = value;
                        break;
                    case "MaxCommandLength":
                        o.Connection.MaxCommandLength = value;
                        break;
                    case "PassiveOverlapsControl":
                        o.PassivePortRange.Start = o.Port;
                        o.PassivePortRange.End = o.Port + 4;
                        break;
                }
            });
        }
        catch (OptionsValidationException)
        {
            failed = true;
        }

        Assert.True(failed, $"configuration '{scenario}' should have been refused at startup");
    }
}
