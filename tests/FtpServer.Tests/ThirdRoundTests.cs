using System.Security.Cryptography;
using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// Regressions for the third review round.
/// </summary>
public class ThirdRoundTests
{
    [Fact]
    public async Task Idle_timeout_rearms_after_a_transfer_completes()
    {
        // Suspending the idle timer during a transfer latched it off: nothing re-timed the
        // blocking read when the transfer ended, so the session never timed out again.
        await using var server = await FtpServerFixture.StartAsync(o => o.Connection.IdleTimeout = TimeSpan.FromSeconds(2));
        server.WriteFile("small.txt", "tiny");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var (data, control) = await client.DownloadAsync("RETR small.txt");
        Assert.Equal("tiny", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);

        // Now genuinely idle: the timer must fire again. Both reads count, since under load the
        // 421 can land inside the download's own window, and a closed connection proves it too.
        var seen = control + await client.ReadAsync(10000);

        if (!seen.Contains("421", StringComparison.Ordinal))
        {
            Assert.True(await client.IsClosedAsync(10000), "the session stayed open after the idle timeout");
        }
    }

    [Fact]
    public async Task A_stalled_transfer_is_abandoned_rather_than_held_open()
    {
        // With the control-channel idle timer suspended during a transfer, a client that opens
        // the data connection and then sends nothing would otherwise keep the session alive
        // indefinitely.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Connection.IdleTimeout = TimeSpan.FromSeconds(30);
            o.DataConnection.InactivityTimeout = TimeSpan.FromSeconds(2);
        });

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();

        // Announce an upload, connect the data port, then send nothing at all.
        await client.SendAsync("STOR stalled.bin", 0);

        var reply = await client.ReadAsync(10000);

        Assert.Matches(@"(?m)^(426|451)", reply);
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task A_client_that_stops_reading_a_download_is_abandoned()
    {
        // The inactivity timeout originally guarded reads only, and a download reads from a local
        // file that never stalls - so a peer that stopped reading blocked the write forever.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Connection.IdleTimeout = TimeSpan.FromSeconds(30);
            o.DataConnection.InactivityTimeout = TimeSpan.FromSeconds(2);
        });

        // Comfortably larger than the socket buffers, so the write cannot simply complete.
        await File.WriteAllBytesAsync(Path.Combine(server.Root, "huge.bin"), new byte[32 * 1024 * 1024]);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();

        // Ask for the file and then never read the data connection.
        await client.SendAsync("RETR huge.bin", 0);

        var reply = await client.ReadAsync(15000);

        Assert.Matches(@"(?m)^(426|451)", reply);
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task A_client_that_stops_reading_an_encrypted_download_is_abandoned()
    {
        // Bounding the data write moved the block rather than removing it for FTPS: tearing the
        // channel down sends a TLS close_notify, which is itself a write, so an un-draining peer
        // stalled disposal instead - and the 426 never got sent.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Ftps = true;
            o.Connection.IdleTimeout = TimeSpan.FromSeconds(60);
            o.DataConnection.InactivityTimeout = TimeSpan.FromSeconds(2);
        });

        await File.WriteAllBytesAsync(Path.Combine(server.Root, "huge.bin"), new byte[32 * 1024 * 1024]);

        await using var client = await server.ConnectAsync();

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("PBSZ 0");
        await client.SendAsync("PROT P");
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();

        await client.SendAsync("RETR huge.bin", 0);

        // Complete the data handshake, then never read a byte.
        await using var ssl = new System.Net.Security.SslStream(data.GetStream(), false, static (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = "localhost" });

        var reply = await client.ReadAsync(20000);

        Assert.Matches(@"(?m)^(426|451)", reply);
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Quit_pipelined_behind_a_transfer_still_gets_its_reply()
    {
        // A finished transfer leaves a one-shot CancelPendingRead latch. With QUIT in the same
        // segment as the transfer command, no read consumes it, so the linger saw IsCanceled and
        // returned at once - exposing the 226/221 to the disposal race it exists to close.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("small.txt", "tiny");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();

        // Both commands in one write, so QUIT is processed in the same buffer iteration.
        var reply = await client.SendRawAsync("RETR small.txt\r\nQUIT\r\n", 600);

        using var buffer = new MemoryStream();
        await data.GetStream().CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(10));

        reply += await client.ReadAsync(5000);

        Assert.Equal("tiny", Encoding.ASCII.GetString(buffer.ToArray()));
        Assert.Contains("226", reply);
        Assert.Contains("221", reply);
    }

    [Fact]
    public async Task Feat_does_not_promise_ranged_transfers()
    {
        // "RANG STREAM" commits the server to honouring octet ranges on RETR and STOR. It does
        // not, and a client acting on that promise would upload a partial payload to a STOR that
        // truncates.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        var reply = await client.SendAsync("FEAT");

        Assert.StartsWith("211-", reply);
        Assert.DoesNotContain("RANG STREAM", reply);
    }

    [Fact]
    public async Task Rang_only_affects_hash_not_the_next_transfer()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("ranged.txt", "0123456789");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("RANG 0 4");

        // The transfer is unaffected by the hash range.
        var (data, _) = await client.DownloadAsync("RETR ranged.txt");
        Assert.Equal("0123456789", Encoding.ASCII.GetString(data));
    }

    [Theory]
    [InlineData("RANG 5 2")]
    [InlineData("RANG")]
    [InlineData("RANG 1")]
    [InlineData("RANG a b")]
    public async Task Malformed_rang_is_a_syntax_error(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync(command));
    }

    [Fact]
    public async Task Rang_one_zero_is_the_reset_form()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("350", await client.SendAsync("RANG 1 0"));
    }

    [Fact]
    public async Task Hash_digests_are_lowercase_and_legacy_digests_upper()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("case.txt", "hello world");

        await using var client = await server.LoginAsync();

        var expected = Convert.ToHexString(SHA256.HashData("hello world"u8.ToArray()));

        // draft-bryan-ftpext-hash section 3 asks for lowercase; the de-facto X* commands use upper.
        Assert.Contains(expected.ToLowerInvariant(), await client.SendAsync("HASH case.txt"));
        Assert.Contains(expected, await client.SendAsync("XSHA256 case.txt"));
    }

    [Fact]
    public async Task Opts_mlst_with_no_factlist_selects_names_only()
    {
        // RFC 3659 section 7.9: no factnames means the client wants only the file names.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "hello");

        await using var client = await server.LoginAsync();

        Assert.Equal("200 MLST OPTS\r\n", await client.SendAsync("OPTS MLST"));

        var (data, _) = await client.DownloadAsync("MLSD");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains(" one.txt", listing);
        Assert.DoesNotContain("type=", listing);
        Assert.DoesNotContain("size=", listing);
    }

    [Fact]
    public async Task Opts_mlst_with_a_malformed_factlist_is_refused_and_changes_nothing()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("one.txt", "hello");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync("OPTS MLST unique type;"));

        // The previous (default) selection is still in force.
        var (data, _) = await client.DownloadAsync("MLSD");
        Assert.Contains("type=file;size=5;", Encoding.UTF8.GetString(data));
    }

    [Fact]
    public async Task Csid_requires_a_login_and_reports_terminated_facts()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.ConnectAsync();

        Assert.StartsWith("530", await client.SendAsync("CSID Name=test;"));

        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");

        var reply = await client.SendAsync("CSID Name=test;");

        Assert.StartsWith("200", reply);
        Assert.Contains("Name=FtpServer;", reply);
        Assert.Contains("CaseSensitive=", reply);
    }

    [Fact]
    public async Task Require_tls_without_ftps_is_refused_at_startup()
    {
        // Otherwise USER is refused until AUTH TLS and AUTH TLS is refused because TLS is off:
        // no client could ever log in, and it would fail per connection instead of once.
        var failed = false;

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.RequireTls = true;
                o.Ftps = false;
            });
        }
        catch (OptionsValidationException)
        {
            failed = true;
        }

        Assert.True(failed);
    }

    [Fact]
    public async Task Require_tls_defers_login_until_the_connection_is_protected()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Ftps = true;
            o.RequireTls = true;
        });

        await using var client = await server.ConnectAsync();

        Assert.StartsWith("534", await client.SendAsync("USER anonymous"));

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();

        Assert.StartsWith("331", await client.SendAsync("USER anonymous"));
        Assert.StartsWith("230", await client.SendAsync("PASS a@b.c"));
    }

    [Fact]
    public async Task A_filesystem_root_is_refused_at_startup()
    {
        var failed = false;

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o => o.Path = OperatingSystem.IsWindows() ? @"C:\" : "/");
        }
        catch (OptionsValidationException)
        {
            failed = true;
        }

        Assert.True(failed);
    }

    [Fact]
    public async Task A_hashed_password_is_accepted()
    {
        // PasswordSha256 is the preferred credential path and had no coverage.
        var hash = Convert.ToHexString(SHA256.HashData("s3cret"u8.ToArray()));

        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "bob", PasswordSha256 = hash });
        });

        await using var client = await server.ConnectAsync();

        await client.SendAsync("USER bob");
        Assert.StartsWith("530", await client.SendAsync("PASS wrong"));

        await client.SendAsync("USER bob");
        Assert.StartsWith("230", await client.SendAsync("PASS s3cret"));
    }

    [Fact]
    public async Task A_base64_hashed_password_is_accepted()
    {
        var hash = Convert.ToBase64String(SHA256.HashData("s3cret"u8.ToArray()));

        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "bob", PasswordSha256 = hash });
        });

        await using var client = await server.ConnectAsync();

        await client.SendAsync("USER bob");
        Assert.StartsWith("230", await client.SendAsync("PASS s3cret"));
    }

    [Fact]
    public async Task A_home_directory_narrows_a_user_to_a_subdirectory()
    {
        // Only the widening rejection was covered; a regression that ignored HomeDirectory
        // entirely would have passed.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new Options.FtpUserOptions
            {
                Name = "bob",
                Password = "secret",
                HomeDirectory = "bobs-area",
            });
        });

        server.WriteFile("outside-the-home.txt", "server root");
        server.WriteFile(Path.Combine("bobs-area", "mine.txt"), "bob's file");

        await using var client = await server.ConnectAsync();
        await client.SendAsync("USER bob");
        Assert.StartsWith("230", await client.SendAsync("PASS secret"));

        var (data, _) = await client.DownloadAsync("NLST");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("mine.txt", listing);
        Assert.DoesNotContain("outside-the-home.txt", listing);
    }

    [Fact]
    public async Task Per_user_read_only_is_enforced()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "ro", Password = "p", ReadOnly = true });
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "rw", Password = "p" });
        });

        await using var readOnly = await server.ConnectAsync();
        await readOnly.SendAsync("USER ro");
        await readOnly.SendAsync("PASS p");
        Assert.StartsWith("550", await readOnly.SendAsync("MKD nope"));

        await using var writable = await server.ConnectAsync();
        await writable.SendAsync("USER rw");
        await writable.SendAsync("PASS p");
        Assert.StartsWith("257", await writable.SendAsync("MKD yes"));
    }

    [Fact]
    public async Task Lockout_expires_and_lets_a_good_login_through()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.MaxFailedAttempts = 1;
            // Long enough that a loaded machine cannot let the lockout expire between the failed
            // attempt and the assertion that it took effect - the test then waits it out
            // explicitly to check the other direction.
            o.Authentication.LockoutDuration = TimeSpan.FromSeconds(8);
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "bob", Password = "secret" });
        });

        await using (var first = await server.ConnectAsync())
        {
            await first.SendAsync("USER bob");
            Assert.StartsWith("530", await first.SendAsync("PASS wrong"));
            Assert.StartsWith("421", await first.SendAsync("USER bob"));
        }

        await Task.Delay(11000);

        await using var second = await server.ConnectAsync();
        await second.SendAsync("USER bob");
        Assert.StartsWith("230", await second.SendAsync("PASS secret"));
    }

    [Fact]
    public async Task Per_address_connection_limit_is_distinct_from_the_total()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Connection.MaxConnections = 100;
            o.Connection.MaxConnectionsPerAddress = 2;
        });

        await using var first = await server.ConnectAsync();
        await using var second = await server.ConnectAsync();
        await using var third = new FtpTestClient(server.Port);

        await third.ConnectAsync();

        Assert.StartsWith("421", third.Banner);
    }
}
