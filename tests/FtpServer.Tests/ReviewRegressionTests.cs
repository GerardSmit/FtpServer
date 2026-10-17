using System.Net;
using System.Net.Sockets;
using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// Regressions for defects found by review after the rewrite. Each test fails against the code as
/// it stood before the corresponding fix.
/// </summary>
public class ReviewRegressionTests
{
    [Fact]
    public async Task Idle_timeout_does_not_fire_during_a_transfer()
    {
        // Running transfers in the background (so ABOR could be received) left the read loop
        // re-arming the idle timer while data flowed, cutting short every transfer slower than
        // IdleTimeout with 421 + 426 and a truncated file.
        await using var server = await FtpServerFixture.StartAsync(o => o.Connection.IdleTimeout = TimeSpan.FromSeconds(2));

        var payload = new byte[8 * 1024 * 1024];
        Random.Shared.NextBytes(payload);
        await File.WriteAllBytesAsync(Path.Combine(server.Root, "big.bin"), payload);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();
        await client.SendAsync("RETR big.bin", 0);

        // Drain slowly so the transfer outlives the idle timeout several times over.
        using var received = new MemoryStream();
        var buffer = new byte[16 * 1024];
        var deadline = DateTime.UtcNow.AddSeconds(6);

        while (DateTime.UtcNow < deadline)
        {
            var read = await data.GetStream().ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));

            if (read == 0)
            {
                break;
            }

            received.Write(buffer, 0, read);
            await Task.Delay(40);
        }

        var control = await client.ReadAsync(500);

        Assert.DoesNotContain("421", control);
        Assert.DoesNotContain("426", control);
        Assert.True(received.Length > 0);
    }

    [Fact]
    public async Task Idle_timeout_still_fires_when_the_session_is_genuinely_idle()
    {
        // The companion to the test above: suppressing the timer during transfers must not
        // disable it outright.
        await using var server = await FtpServerFixture.StartAsync(o => o.Connection.IdleTimeout = TimeSpan.FromSeconds(2));
        await using var client = await server.LoginAsync();

        // Comfortably clear of the 2 s timeout, but still tight enough that a reply which is
        // merely late rather than lost would show up as a failure.
        Assert.StartsWith("421", await client.ReadAsync(10000));
    }

    [Fact]
    public async Task Second_user_command_releases_a_rented_passive_port()
    {
        // SignOut reset the data provider to Active without releasing it, so a PASV followed by a
        // second USER orphaned the reservation: nobody could claim it and nobody could free it.
        // Cycling more times than the pool has ports drains it if each cycle leaks one.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        // More cycles than the pool has ports, so a per-cycle leak drains it.
        for (var cycle = 0; cycle < 20; cycle++)
        {
            Assert.StartsWith("227", await client.SendAsync("PASV"));

            // Restart the login sequence while the port is still rented.
            await client.SendAsync("USER anonymous");
            await client.SendAsync("PASS a@b.c");
        }

        Assert.StartsWith("227", await client.SendAsync("PASV"));
    }

    [Fact]
    public async Task Passive_port_survives_a_client_that_resets_the_connection()
    {
        // The accept loop used to break out on any exception while leaving the port rentable, so
        // one aborted connection poisoned that port for the lifetime of the process. Cycling more
        // times than the pool has ports means a poisoned port cannot simply be skipped over.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("after.txt", "still working");

        await using var client = await server.LoginAsync();

        for (var attempt = 0; attempt < 12; attempt++)
        {
            var reply = await client.SendAsync("PASV");
            var match = System.Text.RegularExpressions.Regex.Match(reply, @"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)");
            Assert.True(match.Success, "PASV failed on attempt " + attempt + ": " + reply);

            var port = (int.Parse(match.Groups[5].Value) << 8) + int.Parse(match.Groups[6].Value);

            // Connect and slam it shut without a graceful close.
            using (var aborter = new TcpClient())
            {
                await aborter.ConnectAsync(IPAddress.Loopback, port);
                aborter.LingerState = new LingerOption(true, 0);
            }

            await Task.Delay(150);
        }

        // The port must still be usable for a real transfer.
        await client.SendAsync("TYPE I");
        var (data, control) = await client.DownloadAsync("RETR after.txt");

        Assert.Equal("still working", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Read_only_mode_refuses_uploads_and_leaves_the_file_alone()
    {
        // The read-only test only covered MKD/RMD/DELE/RNFR, so removing the gate from STOR,
        // APPE or STOU went unnoticed — and it asserted reply codes without checking that the
        // mutation had not happened anyway.
        await using var server = await FtpServerFixture.StartAsync(o => o.ReadOnly = true);
        server.WriteFile("existing.txt", "original");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.StartsWith("550", await client.SendAsync("STOR existing.txt"));
        Assert.StartsWith("550", await client.SendAsync("APPE existing.txt"));
        Assert.StartsWith("550", await client.SendAsync("STOU"));
        Assert.StartsWith("550", await client.SendAsync("MFMT 20200102030405 existing.txt"));
        Assert.StartsWith("550", await client.SendAsync("SITE UTIME existing.txt 20200102030405"));

        Assert.Equal("original", await File.ReadAllTextAsync(Path.Combine(server.Root, "existing.txt")));
        Assert.Single(Directory.GetFiles(server.Root));
    }

    [Theory]
    [InlineData("STOR /../escaped.txt")]
    [InlineData("STOR ../escaped.txt")]
    [InlineData("MKD /../escaped-dir")]
    [InlineData("APPE /../escaped.txt")]
    public async Task Writes_cannot_escape_the_root(string command)
    {
        // Only read escapes were covered. A write escaping the jail is the worst regression
        // available, so it gets its own test.
        await using var server = await FtpServerFixture.StartAsync();

        // Named targets rather than a directory diff: the root's parent is the shared temp
        // directory, which other tests in this run are also writing to.
        var parent = Path.GetDirectoryName(server.Root)!;
        var escapedFile = Path.Combine(parent, "escaped.txt");
        var escapedDir = Path.Combine(parent, "escaped-dir");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        // Whatever the reply, nothing may appear outside the root. ".." is folded away, so these
        // resolve back inside the jail rather than being refused.
        if (command.StartsWith("STOR", StringComparison.Ordinal) || command.StartsWith("APPE", StringComparison.Ordinal))
        {
            // A write command needs a data connection, or it is refused before touching the disk
            // and the test would prove nothing.
            await client.UploadAsync(command, "payload"u8.ToArray());
        }
        else
        {
            await client.SendAsync(command, 400);
        }

        Assert.False(File.Exists(escapedFile), "a write escaped the root: " + escapedFile);
        Assert.False(Directory.Exists(escapedDir), "a directory was created outside the root: " + escapedDir);

        // ".." is folded away rather than refused, so the write must have landed inside the root.
        // Without this a server that rejected every write would also pass.
        var inside = Directory.GetFileSystemEntries(server.Root).Select(Path.GetFileName).ToList();
        Assert.Contains(inside, name => name is "escaped.txt" or "escaped-dir");
    }

    [Fact]
    public async Task Resumed_upload_does_not_destroy_the_existing_prefix()
    {
        // STOR opened with FileMode.Create, which truncates before the seek, so a resumed upload
        // (REST n + STOR, what FileZilla and lftp send) wrote its tail over the start of the file
        // and reported "226 Transfer complete."
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("resume-up.txt", "AAAABBBB");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.StartsWith("350", await client.SendAsync("REST 4"));
        Assert.Contains("226", await client.UploadAsync("STOR resume-up.txt", "CCCC"u8.ToArray()));

        Assert.Equal("AAAACCCC", await File.ReadAllTextAsync(Path.Combine(server.Root, "resume-up.txt")));
    }

    [Fact]
    public async Task Port_after_pasv_switches_back_to_active_mode()
    {
        // PORT stored the endpoint but left the passive provider installed, so the next transfer
        // waited for an inbound connection on the rented port and timed out. RFC 959 section 3.2:
        // the most recent data-port specification wins.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("switch.txt", "active after passive");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.StartsWith("227", await client.SendAsync("PASV"));

        var (data, control) = await client.DownloadActiveAsync("RETR switch.txt");

        Assert.Equal("active after passive", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Quit_really_closes_the_socket()
    {
        // The original assertion could not tell end-of-stream from a read timeout, so a server
        // that replied 221 and kept the connection open passed it.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("221", await client.SendAsync("QUIT"));

        Assert.True(await client.IsClosedAsync(), "the server replied 221 but left the connection open");
    }

    [Fact]
    public async Task Feat_does_not_advertise_auth_tls_when_ftps_is_disabled()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = false);
        await using var client = await server.ConnectAsync();

        var reply = await client.SendAsync("FEAT");

        // Anchored, so the assertion cannot pass on an empty reply.
        Assert.StartsWith("211-", reply);
        Assert.EndsWith("211 End\r\n", reply);
        Assert.DoesNotContain("AUTH TLS", reply);
        Assert.DoesNotContain("\r\n PBSZ", reply);
    }

    [Fact]
    public async Task Login_throttling_locks_out_after_repeated_failures()
    {
        // MaxFailedAttempts/LockoutDuration had no coverage at all.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.MaxFailedAttempts = 2;
            o.Authentication.LockoutDuration = TimeSpan.FromMinutes(1);
            o.Authentication.Users.Add(new Options.FtpUserOptions { Name = "bob", Password = "secret" });
        });

        await using var client = await server.ConnectAsync();

        for (var attempt = 0; attempt < 2; attempt++)
        {
            Assert.StartsWith("331", await client.SendAsync("USER bob"));
            Assert.StartsWith("530", await client.SendAsync("PASS wrong"));
        }

        // The lockout is checked on USER, so the sequence is refused before a password is even
        // asked for — the correct credentials never get a chance.
        Assert.StartsWith("421", await client.SendAsync("USER bob"));
    }

    [Fact]
    public async Task Passive_data_connection_from_another_address_is_refused()
    {
        // Data-connection stealing: the control connection comes from 127.0.0.1, the data
        // connection from 127.0.0.2. The passive pool keys reservations by the control peer, so
        // the accept loop closes it; VerifyPeer is the backstop behind that.
        await using var server = await FtpServerFixture.StartAsync(o => o.DataConnection.Timeout = TimeSpan.FromSeconds(3));
        server.WriteFile("secret.txt", "must not be handed over");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var reply = await client.SendAsync("PASV");
        var match = System.Text.RegularExpressions.Regex.Match(reply, @"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)");
        Assert.True(match.Success);

        var port = (int.Parse(match.Groups[5].Value) << 8) + int.Parse(match.Groups[6].Value);

        using var impostor = new TcpClient(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));

        try
        {
            await impostor.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex) when (ex is SocketException or TimeoutException)
        {
            Assert.Skip("this host does not route 127.0.0.2");
            return;
        }

        // SendAsync reads the reply itself, so capture it here rather than reading again later.
        var transferReply = await client.SendAsync("RETR secret.txt", 500);

        using var buffer = new MemoryStream();

        try
        {
            await impostor.GetStream().CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception ex) when (ex is IOException or TimeoutException)
        {
            // Connection torn down, which is the expected outcome.
        }

        // The reservation is only given up once DataConnection.Timeout elapses.
        transferReply += await client.ReadAsync(6000);

        Assert.Empty(buffer.ToArray());
        Assert.Contains("425", transferReply);
    }
}
