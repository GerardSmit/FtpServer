using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using FtpServer.Authentication;
using FtpServer.IO;
using FtpServer.Options;
using FtpServer.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace FtpServer.Tests;

/// <summary>
/// Regressions for the robustness and security defects fixed before the server was exposed to the
/// internet: stalled peers, endless unauthenticated sessions, a dying accept loop, weak login
/// throttling, clear data under RequireTls, passive port starvation and unbounded uploads.
/// </summary>
public class HardeningTests
{
    // ---- stalled control-connection writes --------------------------------

    [Fact]
    public async Task A_client_that_stops_reading_is_disconnected_by_the_write_timeout()
    {
        // The idle timer only wraps reads, so a client that pipelined commands and then stopped
        // reading used to block the session in a flush for ever, holding its connection slot.
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Connection.WriteTimeout = TimeSpan.FromSeconds(1);
            o.Connection.MaxConnectionsPerAddress = 1;
        });

        using var stalled = new TcpClient();
        await stalled.ConnectAsync(IPAddress.Loopback, server.Port);
        var stream = stalled.GetStream();

        var greeting = new byte[256];
        Assert.True(await stream.ReadAsync(greeting) > 0);

        // Far more reply than the socket buffers and the pipe will hold.
        var request = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("FEAT\r\n", 40_000)));
        _ = Task.Run(async () =>
        {
            try
            {
                await stream.WriteAsync(request);
            }
            catch (IOException)
            {
                // The server closed on us, which is the point.
            }
        });

        // The slot is the one thing an abort gives back.
        var freed = false;
        var deadline = DateTime.UtcNow.AddSeconds(15);

        while (!freed && DateTime.UtcNow < deadline)
        {
            await Task.Delay(500);

            await using var probe = new FtpTestClient(server.Port);
            await probe.ConnectAsync();
            freed = probe.Banner.StartsWith("220", StringComparison.Ordinal);
        }

        Assert.True(freed, "the stalled session kept its connection slot");
    }

    // ---- login deadline ---------------------------------------------------

    [Fact]
    public async Task An_unauthenticated_session_is_closed_after_the_login_timeout_whatever_it_sends()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Connection.LoginTimeout = TimeSpan.FromSeconds(2));
        await using var client = await server.ConnectAsync();

        var started = Stopwatch.StartNew();
        var reply = string.Empty;

        // NOOP is allowed before login, and must not buy the session any more time.
        while (started.Elapsed < TimeSpan.FromSeconds(10) && !reply.Contains("421", StringComparison.Ordinal))
        {
            try
            {
                reply = await client.SendAsync("NOOP", settleMs: 100);
            }
            catch (Exception ex) when (ex is IOException or TimeoutException)
            {
                break;
            }
        }

        Assert.Contains("421 Login timeout.", reply, StringComparison.Ordinal);
        Assert.InRange(started.Elapsed.TotalSeconds, 1.5, 6);
        Assert.True(await client.IsClosedAsync(), "the server sent 421 but left the connection open");
    }

    [Fact]
    public async Task A_logged_in_session_is_not_subject_to_the_login_timeout()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Connection.LoginTimeout = TimeSpan.FromSeconds(3));
        await using var client = await server.LoginAsync();

        await Task.Delay(4500);

        Assert.StartsWith("200", await client.SendAsync("NOOP"));
    }

    // ---- accept loop ------------------------------------------------------

    [Fact]
    public async Task The_accept_loop_survives_failures_and_keeps_accepting()
    {
        var root = Path.Combine(Path.GetTempPath(), "ftpaccept-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);

        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)probe.LocalEndPoint!).Port;
        probe.Dispose();

        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Logging.SetMinimumLevel(LogLevel.None);
        builder.Services.AddFtpServer(options =>
        {
            options.Port = port;
            options.Path = root;
            options.Passive = false;
        });

        using var host = builder.Build();

        using var listener = new FaultyListener(
            host.Services.GetRequiredService<FtpSessionProvider>(),
            host.Services.GetRequiredService<FtpConnectionLimiter>(),
            faults: 3);

        try
        {
            listener.Listen(new IPEndPoint(IPAddress.Loopback, port));

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);

            var buffer = new byte[64];
            var read = await client.GetStream().ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

            Assert.StartsWith("220 ok", Encoding.ASCII.GetString(buffer, 0, read));
            Assert.Equal(3, listener.Faults);
        }
        finally
        {
            await listener.StopAsync();

            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
                // Left for the OS to clean up.
            }
        }
    }

    [Fact]
    public async Task Refusals_are_answered_for_a_bounded_number_of_connections_only()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Connection.MaxConnections = 1;
            o.Connection.MaxConnectionsPerAddress = 0;
        });

        await using var first = await server.ConnectAsync();
        Assert.StartsWith("220", first.Banner);

        var clients = await Task.WhenAll(Enumerable.Range(0, 50).Select(async _ =>
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, server.Port).WaitAsync(TimeSpan.FromSeconds(10));
            return client;
        }));

        var answered = 0;
        var unanswered = 0;

        try
        {
            foreach (var client in clients)
            {
                var buffer = new byte[64];

                try
                {
                    var read = await client.GetStream().ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));

                    if (read > 0 && Encoding.ASCII.GetString(buffer, 0, read).StartsWith("421", StringComparison.Ordinal))
                    {
                        answered++;
                    }
                    else
                    {
                        unanswered++;
                    }
                }
                catch (IOException)
                {
                    unanswered++;
                }
            }
        }
        finally
        {
            foreach (var client in clients)
            {
                client.Dispose();
            }
        }

        Assert.InRange(answered, 1, 32);
        Assert.True(unanswered > 0, "beyond the cap the connections should be closed without the message");
    }

    private sealed class FaultyListener(FtpSessionProvider sessions, FtpConnectionLimiter limiter, int faults)
        : FtpListener(sessions, limiter)
    {
        private int _remaining = faults;
        private int _faults;

        public int Faults => Volatile.Read(ref _faults);

        internal override ValueTask<Socket> AcceptAsync(Socket listener, CancellationToken token)
        {
            if (Interlocked.Decrement(ref _remaining) >= 0)
            {
                throw new SocketException((int)SocketError.ConnectionReset);
            }

            return base.AcceptAsync(listener, token);
        }

        protected override void OnServerFaulted(Exception exception) => Interlocked.Increment(ref _faults);

        protected override async Task OnClientConnectedAsync(FtpSession session, CancellationToken token)
        {
            await session.WriteAsync("220 ok\r\n", token);

            // Returning disposes the connection, which can drop the reply before it has left the
            // send pipe; held until the client hangs up (or the listener stops), as the real
            // handler lingers.
            try
            {
                while (true)
                {
                    var result = await session.Transport.Input.ReadAsync(token);
                    session.Transport.Input.AdvanceTo(result.Buffer.End);

                    if (result.IsCompleted)
                    {
                        break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    // ---- login throttling -------------------------------------------------

    private static readonly string Hashed = PasswordHash.Create("secret", iterations: 20_000);

    private static Task<FtpServerFixture> StartWithUsersAsync(int maxFailedAttempts, bool anonymous = false) =>
        FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = anonymous;
            o.Authentication.MaxFailedAttempts = maxFailedAttempts;
            o.Authentication.LockoutDuration = TimeSpan.FromMinutes(5);
            o.Authentication.Users.Add(new FtpUserOptions { Name = "alice", PasswordHash = Hashed });
        });

    private static IPEndPoint Peer(int last) => new(IPAddress.Parse($"203.0.113.{last}"), 40000);

    private static async Task<FtpAuthenticationStatus> TryAsync(IFtpAuthenticator authenticator, string user, string password, int peer) =>
        (await authenticator.AuthenticatePasswordAsync(user, password, Peer(peer), CancellationToken.None)).Status;

    [Fact]
    public async Task A_successful_login_does_not_clear_the_failures_of_the_address()
    {
        await using var server = await StartWithUsersAsync(maxFailedAttempts: 3, anonymous: true);
        var authenticator = server.Services.GetRequiredService<IFtpAuthenticator>();

        // Different names, so the per-user limit is not what trips.
        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "guess1", "x", 1));
        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "guess2", "x", 1));

        // A login that works, between the guesses, used to reset the count.
        Assert.Equal(FtpAuthenticationStatus.Success, await TryAsync(authenticator, "anonymous", "a@b.c", 1));
        Assert.Equal(FtpAuthenticationStatus.Success, await TryAsync(authenticator, "alice", "secret", 1));

        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "guess3", "x", 1));
        Assert.Equal(FtpAuthenticationStatus.TooManyAttempts, await TryAsync(authenticator, "alice", "secret", 1));
    }

    [Fact]
    public async Task Failures_against_one_user_lock_it_whatever_address_they_come_from()
    {
        await using var server = await StartWithUsersAsync(maxFailedAttempts: 2);
        var authenticator = server.Services.GetRequiredService<IFtpAuthenticator>();

        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "alice", "wrong", 1));
        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "alice", "wrong", 2));

        // A third address, with the right password.
        Assert.Equal(FtpAuthenticationStatus.TooManyAttempts, await TryAsync(authenticator, "alice", "secret", 3));

        // Another user from that address is unaffected.
        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "bob", "wrong", 3));
    }

    [Fact]
    public async Task A_successful_login_clears_the_failures_of_that_user()
    {
        await using var server = await StartWithUsersAsync(maxFailedAttempts: 3);
        var authenticator = server.Services.GetRequiredService<IFtpAuthenticator>();

        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "alice", "wrong", 1));
        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "alice", "wrong", 2));
        Assert.Equal(FtpAuthenticationStatus.Success, await TryAsync(authenticator, "alice", "secret", 3));

        // Two more would have been the fourth and fifth failure had the count survived.
        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "alice", "wrong", 4));
        Assert.Equal(FtpAuthenticationStatus.Failed, await TryAsync(authenticator, "alice", "wrong", 5));
    }

    [Fact]
    public async Task Parallel_guesses_cannot_exceed_the_limit()
    {
        // The count used to be bumped after the password check, which is the slow part, so every
        // connection that arrived while it ran was let through as well.
        await using var server = await StartWithUsersAsync(maxFailedAttempts: 3);
        var authenticator = server.Services.GetRequiredService<IFtpAuthenticator>();

        var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ =>
            Task.Run(() => TryAsync(authenticator, "alice", "wrong", 1))));

        Assert.Equal(3, results.Count(status => status == FtpAuthenticationStatus.Failed));
        Assert.Equal(21, results.Count(status => status == FtpAuthenticationStatus.TooManyAttempts));
    }

    [Fact]
    public async Task An_unknown_user_costs_as_much_time_as_a_wrong_password()
    {
        await using var server = await StartWithUsersAsync(maxFailedAttempts: 0);
        var authenticator = server.Services.GetRequiredService<IFtpAuthenticator>();

        // The first call of each pays for JIT and lazy initialisation.
        await TryAsync(authenticator, "alice", "wrong", 1);
        await TryAsync(authenticator, "nobody", "wrong", 1);

        var known = Stopwatch.StartNew();
        for (var i = 0; i < 5; i++)
        {
            await TryAsync(authenticator, "alice", "wrong", 1);
        }

        known.Stop();

        var unknown = Stopwatch.StartNew();
        for (var i = 0; i < 5; i++)
        {
            await TryAsync(authenticator, "nobody", "wrong", 1);
        }

        unknown.Stop();

        // Without the dummy verification the unknown name returns in microseconds.
        Assert.True(
            unknown.Elapsed >= known.Elapsed * 0.25,
            $"unknown user took {unknown.Elapsed.TotalMilliseconds:0} ms, a known one {known.Elapsed.TotalMilliseconds:0} ms");
    }

    [Fact]
    public async Task User_names_are_made_safe_before_they_are_logged()
    {
        await using var server = await StartWithUsersAsync(maxFailedAttempts: 0);
        var logger = new CapturingLogger<DefaultFtpAuthenticator>();

        var authenticator = new DefaultFtpAuthenticator(
            server.Services.GetRequiredService<FtpOptionsProvider>(),
            server.Services.GetRequiredService<FtpFileSystemFactory>(),
            logger);

        var name = "evil\r\n2000-01-01 INFO forged entry\u0007" + new string('x', 200);
        await authenticator.AuthenticatePasswordAsync(name, "wrong", Peer(1), CancellationToken.None);

        var message = Assert.Single(logger.Messages);

        Assert.Contains("Failed login for evil", message, StringComparison.Ordinal);
        Assert.DoesNotContain('\r', message);
        Assert.DoesNotContain('\n', message);
        Assert.DoesNotContain('\u0007', message);
        Assert.DoesNotContain(new string('x', 100), message, StringComparison.Ordinal);
    }

    [Fact]
    public void Log_text_is_stripped_of_control_characters_and_truncated()
    {
        Assert.Equal("a?b?c", FtpLogText.Sanitise("a\rb\nc"));
        Assert.Equal(FtpLogText.MaxLength, FtpLogText.Sanitise(new string('y', 1000)).Length);
        Assert.Equal(string.Empty, FtpLogText.Sanitise(null));
        Assert.Equal("plain name", FtpLogText.Sanitise("plain name"));
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));

        private sealed class NullScope : IDisposable
        {
            public static NullScope Instance { get; } = new();

            public void Dispose()
            {
            }
        }
    }

    // ---- RequireTls and the data connection -------------------------------

    [Theory]
    [InlineData("LIST")]
    [InlineData("NLST")]
    [InlineData("MLSD")]
    [InlineData("RETR f.txt")]
    [InlineData("STOR g.txt")]
    [InlineData("APPE g.txt")]
    [InlineData("STOU")]
    public async Task Require_tls_refuses_data_transfers_while_the_data_connection_is_clear(string command)
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Ftps = true;
            o.RequireTls = true;
        });

        server.WriteFile("f.txt", "x");

        await using var client = await server.ConnectAsync();
        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("PBSZ 0");

        Assert.StartsWith("521 Data connections must be protected (PROT P).", await client.SendAsync(command));
        Assert.StartsWith("534", await client.SendAsync("PROT C"));

        Assert.StartsWith("200", await client.SendAsync("PROT P"));
        Assert.DoesNotContain("521", await client.SendAsync(command));

        // And it cannot be talked back down.
        Assert.StartsWith("534", await client.SendAsync("PROT C"));
    }

    [Fact]
    public async Task Protected_transfers_work_under_require_tls()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Ftps = true;
            o.RequireTls = true;
        });

        server.WriteFile("f.txt", "secret content");

        await using var client = await server.ConnectAsync();
        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("PBSZ 0");
        await client.SendAsync("PROT P");
        await client.SendAsync("TYPE I");

        using var data = await client.OpenPassiveAsync();
        await client.SendAsync("RETR f.txt", 0);

        await using var ssl = new System.Net.Security.SslStream(data.GetStream(), false, static (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = "localhost" });

        using var buffer = new MemoryStream();
        await ssl.CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Equal("secret content", Encoding.ASCII.GetString(buffer.ToArray()));
    }

    [Fact]
    public async Task Clear_data_is_still_allowed_when_tls_is_not_required()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        server.WriteFile("f.txt", "plain");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var (data, control) = await client.DownloadAsync("RETR f.txt");

        Assert.Equal("plain", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control);
    }

    // ---- passive ports ----------------------------------------------------

    private static Task<FtpServerFixture> StartWithOnePassivePortAsync(TimeSpan dataTimeout) =>
        FtpServerFixture.StartAsync(o =>
        {
            o.PassivePortRange.End = o.PassivePortRange.Start;
            o.DataConnection.Timeout = dataTimeout;
        });

    [Fact]
    public async Task A_passive_port_nobody_connects_to_goes_back_to_the_pool()
    {
        await using var server = await StartWithOnePassivePortAsync(TimeSpan.FromSeconds(3));

        await using var abandoned = await server.LoginAsync();
        await using var other = await server.LoginAsync();

        Assert.StartsWith("227", await abandoned.SendAsync("PASV"));
        Assert.StartsWith("425", await other.SendAsync("PASV"));

        await Task.Delay(4000);

        Assert.StartsWith("227", await other.SendAsync("PASV"));

        // The client that let its port lapse is told so, and keeps its session.
        Assert.Contains("425", await abandoned.SendAsync("LIST"));
        Assert.StartsWith("200", await abandoned.SendAsync("NOOP"));
    }

    [Fact]
    public async Task A_passive_port_is_released_when_the_session_ends_or_a_new_pasv_replaces_it()
    {
        await using var server = await StartWithOnePassivePortAsync(TimeSpan.FromMinutes(5));

        await using (var first = await server.LoginAsync())
        {
            Assert.StartsWith("227", await first.SendAsync("PASV"));
            Assert.StartsWith("227", await first.SendAsync("PASV"));
            Assert.StartsWith("221", await first.SendAsync("QUIT"));
        }

        await using var second = await server.LoginAsync();
        var reply = string.Empty;

        for (var attempt = 0; attempt < 20 && !reply.StartsWith("227", StringComparison.Ordinal); attempt++)
        {
            await Task.Delay(250);
            reply = await second.SendAsync("PASV");
        }

        Assert.StartsWith("227", reply);
    }

    [Fact]
    public async Task A_passive_port_that_failed_to_bind_is_tried_again_after_its_cool_down()
    {
        using var blocker = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        blocker.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
        blocker.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        blocker.Listen(1);
        var port = ((IPEndPoint)blocker.LocalEndPoint!).Port;

        await using var socket = new PassiveSocket(port, NullLogger<PassiveSocket>.Instance, TimeSpan.FromSeconds(1));
        var peer = IPAddress.Parse("203.0.113.9");

        Assert.Null(await socket.TryRentAsync(peer));

        blocker.Dispose();

        // Still cooling down, whatever the port is doing now.
        Assert.Null(await socket.TryRentAsync(peer));

        await Task.Delay(1300);

        using var owner = await socket.TryRentAsync(peer);
        Assert.NotNull(owner);
        Assert.Equal(port, owner.Port);
    }

    // ---- upload size ------------------------------------------------------

    [Fact]
    public async Task An_upload_over_the_limit_is_refused_with_552_and_kept_to_the_limit()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.DataConnection.MaxUploadSize = 1000);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.Contains("226", await client.UploadAsync("STOR small.bin", new byte[500]));
        Assert.Equal(500, new FileInfo(Path.Combine(server.Root, "small.bin")).Length);

        var reply = await client.UploadAsync("STOR big.bin", new byte[5000]);

        Assert.Contains("552 Requested file action aborted. Exceeded storage allocation.", reply, StringComparison.Ordinal);
        Assert.DoesNotContain("226", reply, StringComparison.Ordinal);
        Assert.True(new FileInfo(Path.Combine(server.Root, "big.bin")).Length <= 1000);

        // The session carries on.
        Assert.StartsWith("200", await client.SendAsync("NOOP"));
    }

    [Fact]
    public async Task A_small_compressed_upload_cannot_expand_past_the_limit()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.DataConnection.MaxUploadSize = 1000);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("MODE Z");

        using var compressed = new MemoryStream();

        using (var zlib = new ZLibStream(compressed, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            zlib.Write(new byte[1_000_000]);
        }

        Assert.True(compressed.Length < 1000, "the payload should fit under the limit once compressed");

        var reply = await client.UploadAsync("STOR bomb.bin", compressed.ToArray());

        Assert.Contains("552", reply, StringComparison.Ordinal);
        Assert.True(new FileInfo(Path.Combine(server.Root, "bomb.bin")).Length <= 1000);
    }

    [Fact]
    public async Task An_append_only_gets_the_room_the_limit_leaves()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.DataConnection.MaxUploadSize = 1000);
        File.WriteAllBytes(Path.Combine(server.Root, "log.bin"), new byte[900]);

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.Contains("552", await client.UploadAsync("APPE log.bin", new byte[200]));
        Assert.True(new FileInfo(Path.Combine(server.Root, "log.bin")).Length <= 1000);
    }

    [Fact]
    public async Task Uploads_are_unlimited_by_default()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        Assert.Contains("226", await client.UploadAsync("STOR big.bin", new byte[300_000]));
        Assert.Equal(300_000, new FileInfo(Path.Combine(server.Root, "big.bin")).Length);
    }

    // ---- SITE CHMOD and MFF UNIX.mode -------------------------------------

    [Theory]
    [InlineData("4755")]
    [InlineData("2755")]
    [InlineData("1777")]
    [InlineData("7777")]
    public async Task Chmod_refuses_setuid_setgid_and_sticky(string mode)
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("m.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync($"SITE CHMOD {mode} m.txt"));
    }

    [Theory]
    [InlineData("/")]
    [InlineData(".")]
    public async Task Chmod_refuses_the_root_of_the_file_system(string path)
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        Assert.StartsWith("550", await client.SendAsync($"SITE CHMOD 755 {path}"));
    }

    [Fact]
    public async Task Chmod_still_accepts_ordinary_permission_bits()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("m.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("200", await client.SendAsync("SITE CHMOD 0755 m.txt"));
        Assert.StartsWith("200", await client.SendAsync("SITE CHMOD 644 m.txt"));
    }

    [Fact]
    public async Task Mff_unix_mode_refuses_special_bits_and_the_root()
    {
        if (!Handlers.DefaultFtpCommandHandler.CanSetUnixMode || OperatingSystem.IsWindows())
        {
            return;
        }

        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("m.txt", "x");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync("MFF UNIX.mode=4755; m.txt"));
        Assert.StartsWith("501", await client.SendAsync("MFF UNIX.mode=1777; m.txt"));
        Assert.StartsWith("550", await client.SendAsync("MFF UNIX.mode=0755; /"));
        Assert.StartsWith("213", await client.SendAsync("MFF UNIX.mode=0644; m.txt"));
    }

    // ---- options validation -----------------------------------------------

    public static TheoryData<string> ZeroTimeouts() =>
    [
        nameof(FtpConnectionOptions.IdleTimeout),
        nameof(FtpConnectionOptions.LoginTimeout),
        nameof(FtpConnectionOptions.WriteTimeout),
        nameof(FtpConnectionOptions.TlsHandshakeTimeout),
        nameof(FtpDataConnectionOptions.Timeout),
        nameof(FtpDataConnectionOptions.InactivityTimeout),
        nameof(FtpDataConnectionOptions.ConnectTimeout),
    ];

    [Theory]
    [MemberData(nameof(ZeroTimeouts))]
    public void A_timeout_of_zero_or_less_is_refused(string name)
    {
        foreach (var value in new[] { TimeSpan.Zero, TimeSpan.FromSeconds(-1) })
        {
            var options = new FtpOptions();
            Assert.True(FtpOptionsValidator.Validate(options, out _), "the defaults should be valid");

            if (typeof(FtpConnectionOptions).GetProperty(name) is { } connection)
            {
                connection.SetValue(options.Connection, value);
            }
            else
            {
                typeof(FtpDataConnectionOptions).GetProperty(name)!.SetValue(options.DataConnection, value);
            }

            Assert.False(FtpOptionsValidator.Validate(options, out var error));
            Assert.Contains("greater than zero", error, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void A_negative_upload_limit_is_refused()
    {
        var options = new FtpOptions();
        options.DataConnection.MaxUploadSize = -1;

        Assert.False(FtpOptionsValidator.Validate(options, out _));

        options.DataConnection.MaxUploadSize = 0;
        Assert.True(FtpOptionsValidator.Validate(options, out _));
    }

    [Fact]
    public void A_list_time_zone_this_machine_does_not_know_is_refused()
    {
        var options = new FtpOptions();
        options.List.TimeZone = "Nowhere/Never";

        Assert.False(FtpOptionsValidator.Validate(options, out var error));
        Assert.Contains("List.TimeZone", error, StringComparison.Ordinal);

        options.List.TimeZone = "UTC";
        Assert.True(FtpOptionsValidator.Validate(options, out _));
        Assert.Same(TimeZoneInfo.Utc, options.List.ResolveTimeZone());
    }

    // ---- OPTS UTF8 --------------------------------------------------------

    [Fact]
    public async Task Opts_utf8_on_keeps_refusing_invalid_utf8()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();
        Assert.StartsWith("200", await client.SendAsync("OPTS UTF8 ON"));

        var reply = await client.SendBytesAsync([.. "CWD "u8.ToArray(), 0xC3, 0x28, .. "\r\n"u8.ToArray()]);

        Assert.StartsWith("501", Encoding.ASCII.GetString(reply));
    }
}
