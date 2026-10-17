using System.Net.Sockets;
using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// The gaps the test-quality review listed: failure paths, opt-in inversions, and behaviour that
/// was asserted only through a reply code.
/// </summary>
public class CoverageGapTests
{
    [Fact]
    public async Task Client_disconnecting_mid_upload_does_not_wedge_the_session()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        using (var data = await client.OpenPassiveAsync())
        {
            await client.SendAsync("STOR partial.bin", 0);
            await Task.Delay(150);

            await data.GetStream().WriteAsync(new byte[4096]);
            await data.GetStream().FlushAsync();

            // Abort without a graceful close, mid-transfer.
            data.LingerState = new LingerOption(true, 0);
        }

        var reply = await client.ReadAsync(3000);

        // Whatever the outcome, the client is told and the session survives.
        Assert.Matches(@"(?m)^(226|426|451|550)", reply);
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Passive_pool_exhaustion_is_reported_not_hung()
    {
        // Narrows the fixture's own reserved block to a single port rather than hardcoding one,
        // which would collide as the suite grows or if the machine already uses it.
        await using var server = await FtpServerFixture.StartAsync(o => o.PassivePortRange.End = o.PassivePortRange.Start);

        await using var first = await server.LoginAsync();
        await using var second = await server.LoginAsync();

        Assert.StartsWith("227", await first.SendAsync("PASV"));

        // The only port is taken by a different session on the same address.
        Assert.StartsWith("425", await second.SendAsync("PASV"));
    }

    [Fact]
    public async Task Concurrent_sessions_can_transfer_at_the_same_time()
    {
        // Exercises the port pool's release-by-identity logic under contention.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("shared.txt", "shared payload");

        var clients = new List<FtpTestClient>();

        try
        {
            for (var i = 0; i < 4; i++)
            {
                clients.Add(await server.LoginAsync());
            }

            var downloads = clients.Select(async c =>
            {
                await c.SendAsync("TYPE I");
                var (data, control) = await c.DownloadAsync("RETR shared.txt");
                return (Text: Encoding.ASCII.GetString(data), Control: control);
            });

            foreach (var result in await Task.WhenAll(downloads))
            {
                Assert.Equal("shared payload", result.Text);
                Assert.Contains("226", result.Control);
            }
        }
        finally
        {
            foreach (var c in clients)
            {
                await c.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task Epsv_advertises_a_port_that_actually_works()
    {
        // Only the reply string was checked before; nothing connected to the advertised port.
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("epsv.txt", "over extended passive");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var reply = await client.SendAsync("EPSV");
        var match = System.Text.RegularExpressions.Regex.Match(reply, @"\(\|\|\|(\d+)\|\)");
        Assert.True(match.Success, reply);

        using var data = new TcpClient();
        await data.ConnectAsync(System.Net.IPAddress.Loopback, int.Parse(match.Groups[1].Value));

        await client.SendAsync("RETR epsv.txt", 0);

        using var buffer = new MemoryStream();
        await data.GetStream().CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal("over extended passive", Encoding.ASCII.GetString(buffer.ToArray()));
    }

    [Fact]
    public async Task Allowing_a_foreign_data_host_is_opt_in_and_takes_effect()
    {
        // Without this, silently inverting the bounce guard's default would be undetectable.
        await using var server = await FtpServerFixture.StartAsync(o => o.DataConnection.AllowForeignHost = true);
        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("PORT 93,184,216,34,31,144"));
    }

    [Fact]
    public async Task Oversized_command_closes_the_connection()
    {
        // The documented behaviour is 500 *and* close; only the reply was covered before.
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("500", await client.SendAsync(new string('A', 5000), 500));
        Assert.True(await client.IsClosedAsync(), "the server replied 500 but left the connection open");
    }

    [Fact]
    public async Task A_command_line_at_the_limit_is_still_accepted()
    {
        await using var server = await FtpServerFixture.StartAsync();
        await using var client = await server.LoginAsync();

        // 4096 total including CRLF: a verb, a space, and a long argument.
        var argument = new string('a', 4096 - 2 - "CWD ".Length);

        Assert.StartsWith("550", await client.SendAsync("CWD " + argument, 400));
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Connection_slots_are_released_when_a_client_disconnects()
    {
        // A limiter that leaks a slot would only show up after the limit is reached.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Connection.MaxConnections = 2;
            o.Connection.MaxConnectionsPerAddress = 2;
        });

        for (var i = 0; i < 6; i++)
        {
            await using var client = await server.ConnectAsync();
            Assert.StartsWith("220", client.Banner);
            await client.SendAsync("QUIT");

            // Give the server a moment to notice the close and release the lease.
            await Task.Delay(120);
        }
    }

    [Fact]
    public async Task Prot_c_after_prot_p_returns_the_data_connection_to_cleartext()
    {
        // Previously only the 200 reply was asserted, never that a transfer actually followed it.
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        server.WriteFile("clear.txt", "sent in the clear");

        await using var client = await server.ConnectAsync();

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("PBSZ 0");
        await client.SendAsync("PROT P");
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("TYPE I");

        Assert.StartsWith("200", await client.SendAsync("PROT C"));

        // No TLS handshake on the data connection this time.
        var (data, control) = await client.DownloadAsync("RETR clear.txt");

        Assert.Equal("sent in the clear", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
    }

    [Fact]
    public async Task Restart_past_the_end_of_the_file_is_refused()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("short.txt", "abc");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("REST 100");

        using var data = await client.OpenPassiveAsync();
        var reply = await client.SendAsync("RETR short.txt", 600);

        Assert.Contains("554", reply);
    }

    [Fact]
    public async Task Restart_offset_does_not_survive_into_a_later_transfer()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("marker.txt", "0123456789");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("REST 5");

        var (first, _) = await client.DownloadAsync("RETR marker.txt");
        Assert.Equal("56789", Encoding.ASCII.GetString(first));

        // The marker is consumed by that transfer, not remembered.
        var (second, _) = await client.DownloadAsync("RETR marker.txt");
        Assert.Equal("0123456789", Encoding.ASCII.GetString(second));
    }

    [Fact]
    public async Task Non_ascii_names_survive_the_machine_listing()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("café-日本.txt", "unicode");

        await using var client = await server.LoginAsync();
        await client.SendAsync("OPTS UTF8 ON");

        var (data, _) = await client.DownloadAsync("MLSD");
        var listing = Encoding.UTF8.GetString(data);

        Assert.Contains("café-日本.txt", listing);

        var reply = await client.SendAsync("MLST café-日本.txt");
        Assert.Contains("café-日本.txt", reply);
    }

    [Fact]
    public async Task Mfmt_on_a_directory_is_handled()
    {
        await using var server = await FtpServerFixture.StartAsync();
        Directory.CreateDirectory(Path.Combine(server.Root, "stamped"));

        await using var client = await server.LoginAsync();

        var reply = await client.SendAsync("MFMT 20200102030405 stamped");

        Assert.Matches(@"^(213|550)", reply);
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }

    [Fact]
    public async Task Plain_client_on_a_protected_data_port_does_not_hang_the_session()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Ftps = true;
            o.DataConnection.Timeout = TimeSpan.FromSeconds(3);
            o.Connection.TlsHandshakeTimeout = TimeSpan.FromSeconds(3);
        });
        server.WriteFile("secure.txt", "tls only");

        await using var client = await server.ConnectAsync();

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("PBSZ 0");
        await client.SendAsync("PROT P");
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("TYPE I");

        using (var data = await client.OpenPassiveAsync())
        {
            // Connect but never complete the TLS handshake the server is waiting for.
            await client.SendAsync("RETR secure.txt", 0);
            await Task.Delay(500);
        }

        var reply = await client.ReadAsync(8000);

        Assert.Matches(@"(?m)^(425|426|451|550)", reply);
        Assert.StartsWith("257", await client.SendAsync("PWD"));
    }
}
