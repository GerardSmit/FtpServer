using System.Text;
using FtpServer.Authentication;

namespace FtpServer.Tests;

/// <summary>
/// Regressions for the conformance defects found in the implementation review.
/// </summary>
public class ReviewFixTests
{
    // ---- FTP-002: AUTH TLS resets the session ------------------------------

    [Fact]
    public async Task Auth_tls_discards_the_identity_and_the_transfer_parameters()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.Ftps = true);
        server.WriteFile("sub/file.txt", "content");

        await using var client = await server.LoginAsync();
        await client.SendAsync("CWD sub");
        await client.SendAsync("TYPE I");

        Assert.StartsWith("234", await client.SendAsync("AUTH TLS"));
        await client.StartTlsAsync();

        // RFC 4217 section 4: the client must reauthorize, and every other transfer parameter is
        // reset as if REIN had been issued.
        Assert.StartsWith("530", await client.SendAsync("PWD"));

        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");

        Assert.Contains("\"/\"", await client.SendAsync("PWD"), StringComparison.Ordinal);

        // TYPE is back at the default, which ASCII-translates the line ending.
        server.WriteFile("crlf.txt", "a\nb");
        var (data, _) = await client.DownloadAsync("RETR crlf.txt");

        Assert.Equal("a\r\nb", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Auth_tls_keeps_a_host_the_handshake_agrees_with()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.Ftps = true);

        await using var client = await server.ConnectAsync();
        Assert.StartsWith("220", await client.SendAsync("HOST localhost"));

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync(targetHost: "localhost");

        // The host selects the server, not the user, so it survives the security-layer change.
        Assert.Contains("Virtual host: localhost", await client.SendAsync("STAT"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_that_contradicts_the_tls_server_name_is_refused()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.Ftps = true);

        await using var client = await server.ConnectAsync();
        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync(targetHost: "sni.example.com");

        // The certificate presented was chosen for the name in the handshake.
        Assert.StartsWith("504", await client.SendAsync("HOST other.example.com"));
        Assert.DoesNotContain("Virtual host", await client.SendAsync("STAT"), StringComparison.Ordinal);

        Assert.StartsWith("220", await client.SendAsync("HOST sni.example.com"));
        Assert.Contains("Virtual host: sni.example.com", await client.SendAsync("STAT"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_chosen_before_a_contradicting_handshake_is_dropped()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.Ftps = true);

        await using var client = await server.ConnectAsync();
        await client.SendAsync("HOST first.example.com");

        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync(targetHost: "second.example.com");

        // RFC 7151 section 3.3 option a: the connection carries on as though no HOST had been
        // sent, so the client can name one the handshake agrees with.
        Assert.DoesNotContain("Virtual host", await client.SendAsync("STAT"), StringComparison.Ordinal);
        Assert.StartsWith("220", await client.SendAsync("HOST second.example.com"));
    }

    // ---- FTP-003: REIN clears the security layer ---------------------------

    [Fact]
    public async Task Rein_returns_the_control_connection_to_the_clear()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.Ftps = true);

        await using var client = await server.ConnectAsync();
        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("PBSZ 0");
        await client.SendAsync("PROT P");

        // RFC 4217 section 13: the reply is sent inside TLS, and the session is cleared after it.
        Assert.StartsWith("220", await client.SendAsync("REIN"));

        client.StopTls();

        Assert.StartsWith("530", await client.SendAsync("PWD"));

        // PROT is negotiated again from scratch: the earlier PBSZ went with the TLS session.
        Assert.StartsWith("503", await client.SendAsync("PROT P"));
        Assert.Contains("control connection is in the clear", await client.SendAsync("STAT"), StringComparison.Ordinal);
    }

    // ---- FTP-004: RFC 7151 HOST -------------------------------------------

    [Theory]
    [InlineData("HOST ftp..example.com")]
    [InlineData("HOST -leading.example.com")]
    [InlineData("HOST trailing-.example.com")]
    [InlineData("HOST [192.0.2.1]")]
    [InlineData("HOST [IPv6:::1]")]
    [InlineData("HOST ")]
    public async Task Malformed_host_is_a_syntax_error(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.ConnectAsync();

        Assert.StartsWith("501", await client.SendAsync(command));
    }

    [Fact]
    public async Task Address_literal_that_is_not_ours_is_refused()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.ConnectAsync();

        // RFC 7151 section 3.2.1: a literal that is not the server's own address is not a host it
        // can serve.
        Assert.StartsWith("504", await client.SendAsync("HOST 192.0.2.1"));

        // The connection stays in the no-HOST state, so another name may still be given.
        Assert.StartsWith("220", await client.SendAsync("HOST 127.0.0.1"));

        // The test client connects over IPv4 loopback, so the IPv6 loopback literal is a
        // different address and is refused for the same reason.
        Assert.StartsWith("504", await client.SendAsync("HOST [::1]"));
    }

    [Fact]
    public async Task Address_literal_of_the_public_address_is_accepted()
    {
        // Behind NAT or in a container clients name the public address, not the local endpoint's.
        await using var server = await FtpServerFixture.StartAsync(o => o.DataConnection.PublicAddress = "192.0.2.1");

        await using var client = await server.ConnectAsync();

        Assert.StartsWith("220", await client.SendAsync("HOST 192.0.2.1"));
        Assert.StartsWith("504", await client.SendAsync("HOST 192.0.2.2"));
    }

    [Fact]
    public async Task Second_host_resets_the_authentication_environment()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.ConnectAsync();
        await client.SendAsync("HOST a.example.com");
        await client.SendAsync("USER anonymous");

        Assert.StartsWith("220", await client.SendAsync("HOST b.example.com"));

        // RFC 7151 section 4: the pending user name belonged to the previous host.
        Assert.StartsWith("503", await client.SendAsync("PASS a@b.c"));
    }

    // ---- FTP-005: default data port ---------------------------------------

    [Fact]
    public async Task Transfer_without_port_or_pasv_uses_the_default_data_port()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("file.txt", "default port");

        await using var client = await server.LoginAsync();

        // RFC 959 section 3.3: with no PORT and no passive command the server dials the client's
        // control port. Nothing is listening there, so the transfer starts and fails to connect -
        // rather than being refused outright, as a server with no default data port would.
        var reply = await client.SendAsync("RETR file.txt", settleMs: 2000);

        Assert.Contains("425 Can't open data connection.", reply, StringComparison.Ordinal);
        Assert.DoesNotContain("Use PORT or PASV first", reply, StringComparison.Ordinal);
    }

    // ---- FTP-006: RNFR/RNTO sequencing ------------------------------------

    [Fact]
    public async Task Rename_sequence_is_abandoned_by_anything_in_between()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("a.txt", "a");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("350", await client.SendAsync("RNFR a.txt"));
        await client.SendAsync("NOOP");

        // RFC 959 sections 4.1.3 and 5.4: RNTO must follow RNFR immediately.
        Assert.StartsWith("503", await client.SendAsync("RNTO b.txt"));
        Assert.True(File.Exists(Path.Combine(server.Root, "a.txt")));

        // A failed RNFR also ends the sequence rather than leaving the earlier one armed.
        Assert.StartsWith("350", await client.SendAsync("RNFR a.txt"));
        Assert.StartsWith("550", await client.SendAsync("RNFR missing.txt"));
        Assert.StartsWith("503", await client.SendAsync("RNTO b.txt"));
        Assert.True(File.Exists(Path.Combine(server.Root, "a.txt")));
    }

    // ---- FTP-007: REST with APPE ------------------------------------------

    [Fact]
    public async Task Restart_marker_makes_append_behave_like_store()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("file.txt", "0123456789");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");
        await client.SendAsync("REST 4");

        // RFC 3659 section 5.3: an accepted restart marker makes APPE act exactly as STOR would,
        // so the data lands at the marker instead of at the end - and, as with STOR, the file
        // ends where the resumed data does.
        Assert.Contains("226", await client.UploadAsync("APPE file.txt", "ABC"u8.ToArray()), StringComparison.Ordinal);
        Assert.Equal("0123ABC", File.ReadAllText(Path.Combine(server.Root, "file.txt")));
    }

    // ---- FTP-008/017: MLSx facts ------------------------------------------

    [Fact]
    public async Task Mlsd_omits_the_dot_entries_when_the_type_fact_is_off()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("sub/file.txt", "x");

        await using var client = await server.LoginAsync();
        await client.SendAsync("OPTS MLST");

        var (data, _) = await client.DownloadAsync("MLSD sub");
        var listing = Encoding.ASCII.GetString(data);

        // RFC 3659 sections 7.5.1.2 and 7.5.1.4 identify the current and parent entries by their
        // type fact; without it they are names the client cannot interpret.
        Assert.DoesNotContain(" .\r\n", listing, StringComparison.Ordinal);
        Assert.DoesNotContain(" ..\r\n", listing, StringComparison.Ordinal);
        Assert.Contains("file.txt", listing, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("OPTS MLST size;;modify;")]
    [InlineData("OPTS MLST size;modify")]
    public async Task Malformed_fact_list_is_refused(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync(command));
    }

    // ---- FTP-009/010: representation type ---------------------------------

    [Fact]
    public async Task Default_representation_is_ascii()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("file.txt", "a\nb");

        await using var client = await server.LoginAsync();

        // No TYPE command: RFC 959 sections 3.1.1 and 5.1 leave ASCII Non-print in force.
        var (data, _) = await client.DownloadAsync("RETR file.txt");

        Assert.Equal("a\r\nb", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Ascii_size_is_answered_for_a_large_file()
    {
        await using var server = await FtpServerFixture.StartAsync();

        // Large enough to rule out a size threshold on the measurement.
        const int lines = 3 * 1024 * 1024;
        var path = Path.Combine(server.Root, "big.txt");

        await using (var writer = new StreamWriter(path))
        {
            writer.NewLine = "\n";

            for (var i = 0; i < lines; i++)
            {
                await writer.WriteLineAsync("0123456789012345678901234567890");
            }
        }

        var onDisk = new FileInfo(path).Length;

        await using var client = await server.LoginAsync();

        // Each of the LF line endings gains a CR on the wire.
        var expected = onDisk + lines;

        Assert.Equal($"213 {expected}\r\n", await client.SendAsync("SIZE big.txt", settleMs: 1000));

        // Asked twice, as a resuming client does, and answered the same both times.
        Assert.Equal($"213 {expected}\r\n", await client.SendAsync("SIZE big.txt", settleMs: 1000));
    }

    [Fact]
    public async Task Bare_carriage_return_travels_as_cr_nul()
    {
        await using var server = await FtpServerFixture.StartAsync();
        File.WriteAllBytes(Path.Combine(server.Root, "cr.bin"), "a\rb"u8.ToArray());

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("RETR cr.bin");

        // RFC 959 section 3.1.1.1: NVT-ASCII has no bare CR, so one that does not begin a line
        // ending is escaped with a NUL.
        Assert.Equal("a\r\0b"u8.ToArray(), data);
    }

    [Fact]
    public async Task Uploaded_cr_nul_is_stored_as_a_bare_carriage_return()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        Assert.Contains("226", await client.UploadAsync("STOR cr.bin", "a\r\0b"u8.ToArray()), StringComparison.Ordinal);
        Assert.Equal("a\rb"u8.ToArray(), File.ReadAllBytes(Path.Combine(server.Root, "cr.bin")));
    }

    [Fact]
    public async Task Type_a_t_is_accepted_as_ascii()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        // RFC 1123 section 4.1.2.2: a host with no Telnet-format distinction treats it as
        // Non-print rather than refusing it.
        Assert.StartsWith("200", await client.SendAsync("TYPE A T"));
        Assert.StartsWith("504", await client.SendAsync("TYPE A C"));
    }

    // ---- FTP-011/016: argument decoding -----------------------------------

    [Fact]
    public async Task Invalid_utf8_is_refused_rather_than_replaced()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.LoginAsync();

        // "C3 28" is a lead byte followed by something that cannot continue it. RFC 2640
        // section 3.1 requires validity checking rather than replacement.
        var reply = await client.SendBytesAsync([.. "CWD "u8.ToArray(), 0xC3, 0x28, .. "\r\n"u8.ToArray()]);

        Assert.StartsWith("501", Encoding.ASCII.GetString(reply));
    }

    [Fact]
    public async Task Over_long_argument_is_refused_rather_than_truncated()
    {
        await using var server = await FtpServerFixture.StartAsync(
            options => options.Connection.MaxCommandLength = 64 * 1024);

        await using var client = await server.LoginAsync();

        Assert.StartsWith("501", await client.SendAsync("CWD " + new string('a', 16 * 1024)));
    }

    // ---- FTP-013/014: listings --------------------------------------------

    [Fact]
    public async Task Nlst_of_another_directory_returns_usable_pathnames()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("sub/file.txt", "content");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("NLST sub");

        // RFC 1123 section 4.1.2.7: every name must work as the argument of a later transfer
        // command, which a bare "file.txt" would not from the root.
        Assert.Equal("/sub/file.txt\r\n", Encoding.ASCII.GetString(data));

        var (again, control) = await client.DownloadAsync("RETR /sub/file.txt");
        Assert.Contains("226", control, StringComparison.Ordinal);
        Assert.Equal("content", Encoding.ASCII.GetString(again));
    }

    [Fact]
    public async Task Mlsd_treats_a_leading_dash_as_part_of_the_pathname()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("-dir/inside.txt", "x");

        await using var client = await server.LoginAsync();

        var (data, _) = await client.DownloadAsync("MLSD -dir");

        // MLSD takes a pathname, never ls flags, so this lists "-dir" and not the working
        // directory.
        Assert.Contains("inside.txt", Encoding.ASCII.GetString(data), StringComparison.Ordinal);
    }

    // ---- FTP-015: MDTM ----------------------------------------------------

    [Fact]
    public async Task Mdtm_refuses_a_directory()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("sub/file.txt", "x");

        await using var client = await server.LoginAsync();

        // RFC 3659 section 3 defines MDTM over retrievable objects only.
        Assert.StartsWith("550", await client.SendAsync("MDTM sub"));
        Assert.StartsWith("213", await client.SendAsync("MDTM sub/file.txt"));
    }

    // ---- FTP-019: Telnet negotiation --------------------------------------

    [Fact]
    public async Task Telnet_option_requests_are_answered()
    {
        await using var server = await FtpServerFixture.StartAsync();

        await using var client = await server.ConnectAsync();

        // IAC WILL ECHO, IAC DO ECHO, then NOOP. RFC 1123 section 4.1.2.12: an option request is
        // refused rather than ignored.
        var reply = await client.SendBytesAsync([0xFF, 0xFB, 0x01, 0xFF, 0xFD, 0x01, .. "NOOP\r\n"u8.ToArray()]);

        // IAC DONT ECHO answers the WILL, IAC WONT ECHO answers the DO.
        Assert.Equal([0xFF, 0xFE, 0x01, 0xFF, 0xFC, 0x01], reply[..6]);
        Assert.StartsWith("200", Encoding.ASCII.GetString(reply[6..]));
    }

    // ---- Per-user containment ---------------------------------------------

    [Fact]
    public async Task A_second_login_does_not_inherit_the_previous_home()
    {
        await using var server = await FtpServerFixture.StartAsync(options =>
        {
            options.Authentication.AllowAnonymous = false;
            options.Authentication.Users.Add(new Options.FtpUserOptions
            {
                Name = "alice",
                Password = "alice-password",
                HomeDirectory = "alice",
            });

            options.Authentication.Users.Add(new Options.FtpUserOptions
            {
                Name = "bob",
                Password = "bob-password",
            });
        });

        server.WriteFile("alice/secret.txt", "alice's file");
        server.WriteFile("shared.txt", "everyone's file");

        await using var client = await server.ConnectAsync();
        await client.SendAsync("USER alice");
        await client.SendAsync("PASS alice-password");

        var (aliceListing, _) = await client.DownloadAsync("NLST");
        Assert.Contains("secret.txt", Encoding.ASCII.GetString(aliceListing), StringComparison.Ordinal);

        // Bob has no home of his own, so he gets the server root rather than Alice's.
        await client.SendAsync("USER bob");
        await client.SendAsync("PASS bob-password");

        var (bobListing, _) = await client.DownloadAsync("NLST");
        var listing = Encoding.ASCII.GetString(bobListing);

        Assert.Contains("shared.txt", listing, StringComparison.Ordinal);
        Assert.DoesNotContain("secret.txt", listing, StringComparison.Ordinal);
    }

    // ---- CODE-006: password hashing ---------------------------------------

    [Fact]
    public void Pbkdf2_hash_round_trips_and_rejects_everything_else()
    {
        var hash = PasswordHash.Create("correct horse", iterations: 1000);

        Assert.True(PasswordHash.Verify(hash, "correct horse"));
        Assert.False(PasswordHash.Verify(hash, "correct horse "));
        Assert.False(PasswordHash.Verify(hash, string.Empty));

        // Two hashes of one password differ, because each carries its own salt.
        Assert.NotEqual(hash, PasswordHash.Create("correct horse", iterations: 1000));

        // A malformed stored hash verifies nothing rather than everything.
        Assert.False(PasswordHash.Verify("not-a-hash", "correct horse"));
        Assert.False(PasswordHash.Verify("pbkdf2-sha256$0$$", "correct horse"));
    }

    [Fact]
    public async Task Pbkdf2_password_authenticates()
    {
        var hash = PasswordHash.Create("s3cret", iterations: 1000);

        await using var server = await FtpServerFixture.StartAsync(options =>
        {
            options.Authentication.AllowAnonymous = false;
            options.Authentication.Users.Add(new Options.FtpUserOptions
            {
                Name = "carol",
                PasswordHash = hash,
            });
        });

        await using var client = await server.ConnectAsync();
        await client.SendAsync("USER carol");

        Assert.StartsWith("530", await client.SendAsync("PASS wrong"));

        await client.SendAsync("USER carol");
        Assert.StartsWith("230", await client.SendAsync("PASS s3cret"));
    }
}
