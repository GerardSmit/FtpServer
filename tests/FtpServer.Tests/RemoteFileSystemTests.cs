using System.Security.Cryptography.X509Certificates;
using System.Text;
using FtpServer.Authentication;
using FtpServer.IO;
using Microsoft.Extensions.DependencyInjection;
using Zio;
using Zio.FileSystems;

namespace FtpServer.Tests;

/// <summary>
/// A tree with no host path behind it, and a certificate replaced while the server runs: what an
/// application serving files from other machines needs.
/// </summary>
public class RemoteFileSystemTests
{
    [Fact]
    public async Task A_replaced_certificate_is_presented_to_new_connections()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.Ftps = true);

        await using (var before = await server.ConnectAsync())
        {
            await before.SendAsync("AUTH TLS");
            await before.StartTlsAsync();
            Assert.Contains("CN=localhost", before.RemoteCertificate!.Subject, StringComparison.Ordinal);
        }

        var replacement = CertificateProvider.CreateSelfSignedCertificate("ftp.example.test", 2048);
        server.Services.GetRequiredService<CertificateProvider>().Use(new X509Certificate2Collection(replacement));

        await using var after = await server.ConnectAsync();
        await after.SendAsync("AUTH TLS");
        await after.StartTlsAsync();

        Assert.Contains("CN=ftp.example.test", after.RemoteCertificate!.Subject, StringComparison.Ordinal);
        Assert.StartsWith("331", await after.SendAsync("USER anonymous"));
        Assert.StartsWith("230", await after.SendAsync("PASS a@b.c"));
    }

    [Fact]
    public async Task An_open_session_keeps_its_certificate_for_data_connections_after_a_replacement()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.Ftps = true);
        server.WriteFile("data.txt", "protected payload");

        await using var client = await server.ConnectAsync();
        await client.SendAsync("AUTH TLS");
        await client.StartTlsAsync();
        await client.SendAsync("PBSZ 0");
        await client.SendAsync("PROT P");
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        await client.SendAsync("TYPE I");

        var replacement = CertificateProvider.CreateSelfSignedCertificate("ftp.example.test", 2048);
        server.Services.GetRequiredService<CertificateProvider>().Use(new X509Certificate2Collection(replacement));

        // A data connection presenting the new certificate could not resume the control
        // connection's TLS session, which clients such as FileZilla insist on.
        using var data = await client.OpenPassiveAsync();
        await client.SendAsync("RETR data.txt", 0);

        await using var ssl = new System.Net.Security.SslStream(data.GetStream(), false, static (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = "localhost" });

        using var buffer = new MemoryStream();
        await ssl.CopyToAsync(buffer).WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Contains("CN=localhost", ssl.RemoteCertificate!.Subject, StringComparison.Ordinal);
        Assert.Equal("protected payload", Encoding.ASCII.GetString(buffer.ToArray()));

        // A new session gets the replacement.
        await using var fresh = await server.ConnectAsync();
        await fresh.SendAsync("AUTH TLS");
        await fresh.StartTlsAsync();
        Assert.Contains("CN=ftp.example.test", fresh.RemoteCertificate!.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void A_certificate_without_a_private_key_is_refused()
    {
        using var withKey = CertificateProvider.CreateSelfSignedCertificate("ftp.example.test", 2048);
        using var publicOnly = X509CertificateLoader.LoadCertificate(withKey.Export(X509ContentType.Cert));

        using var provider = new CertificateProvider(
            Microsoft.Extensions.Options.Options.Create(new Options.FtpOptions()),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CertificateProvider>.Instance);

        Assert.Throws<InvalidOperationException>(() => provider.Use(new X509Certificate2Collection(publicOnly)));
    }

    [Fact]
    public async Task Legacy_checksums_are_computed_by_the_remote_file_system()
    {
        var fileSystem = new RemoteMemoryFileSystem();
        await using var server = await StartAsync(fileSystem);
        await using var client = await LoginAsync(server);

        Assert.Equal("250 DEADBEEF\r\n", await client.SendAsync("XCRC /file.txt"));
        Assert.Equal(("/file.txt", "CRC32", 0L, 5L), fileSystem.LastChecksum);
    }

    [Fact]
    public async Task Hash_is_computed_by_the_remote_file_system()
    {
        var fileSystem = new RemoteMemoryFileSystem();
        await using var server = await StartAsync(fileSystem);
        await using var client = await LoginAsync(server);

        var reply = await client.SendAsync("HASH /file.txt");

        Assert.StartsWith("213 SHA-256 0-4 deadbeef /file.txt", reply, StringComparison.Ordinal);
        Assert.Equal("SHA-256", fileSystem.LastChecksum?.Algorithm);
    }

    [Fact]
    public async Task A_remote_file_system_may_leave_a_checksum_to_the_server()
    {
        var fileSystem = new RemoteMemoryFileSystem { Digest = null };
        await using var server = await StartAsync(fileSystem);
        await using var client = await LoginAsync(server);

        // CRC32 of "hello", computed from the stream because the remote declined.
        Assert.Equal("250 3610A686\r\n", await client.SendAsync("XCRC /file.txt"));
    }

    [Fact]
    public async Task Available_space_comes_from_the_remote_file_system()
    {
        await using var server = await StartAsync(new RemoteMemoryFileSystem());
        await using var client = await LoginAsync(server);

        Assert.Equal("213 12345\r\n", await client.SendAsync("AVBL /"));
    }

    [Fact]
    public async Task Listings_of_a_remote_tree_never_ask_for_a_host_path()
    {
        var fileSystem = new RemoteMemoryFileSystem();
        await using var server = await StartAsync(fileSystem);
        await using var client = await LoginAsync(server);

        var (list, listControl) = await client.DownloadAsync("LIST /");
        var (mlsd, mlsdControl) = await client.DownloadAsync("MLSD /");

        Assert.Contains("226", listControl);
        Assert.Contains("226", mlsdControl);
        Assert.Contains("-rw-r--r-- 1 ftp ftp 5", Encoding.UTF8.GetString(list), StringComparison.Ordinal);
        Assert.Contains("perm=", Encoding.UTF8.GetString(mlsd), StringComparison.Ordinal);
        Assert.Equal(0, fileSystem.InternalPathRequests);
    }

    [Fact]
    public async Task A_directory_the_remote_side_cannot_read_is_an_error_not_an_empty_listing()
    {
        // A worker that cannot be reached, or refuses the folder, must not look like an empty folder.
        var fileSystem = new RemoteMemoryFileSystem { UnreadableDirectory = "/locked" };
        await using var server = await StartAsync(fileSystem);
        await using var client = await LoginAsync(server);

        Assert.StartsWith("450", await client.SendAsync("LIST /locked"));
        Assert.StartsWith("450", await client.SendAsync("MLSD /locked"));
        Assert.StartsWith("450", await client.SendAsync("NLST /locked"));

        var (list, control) = await client.DownloadAsync("LIST /");
        Assert.Contains("226", control);
        Assert.Contains("locked", Encoding.UTF8.GetString(list), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Chmod_and_symlinks_are_not_attempted_on_a_remote_tree()
    {
        var fileSystem = new RemoteMemoryFileSystem();
        await using var server = await StartAsync(fileSystem);
        await using var client = await LoginAsync(server);

        Assert.StartsWith("200", await client.SendAsync("SITE CHMOD 644 /file.txt"));
        Assert.DoesNotMatch("^2", await client.SendAsync("SITE SYMLINK /file.txt /link.txt"));
        Assert.Equal(0, fileSystem.InternalPathRequests);
    }

    [Fact]
    public async Task Mff_refuses_the_unix_mode_of_a_remote_tree_and_feat_does_not_offer_it()
    {
        var fileSystem = new RemoteMemoryFileSystem();
        await using var server = await StartAsync(fileSystem);
        await using var client = await LoginAsync(server);

        var mff = (await client.SendAsync("FEAT")).Split("\r\n").Single(line => line.StartsWith(" MFF ", StringComparison.Ordinal));
        Assert.DoesNotContain("UNIX.mode", mff, StringComparison.Ordinal);
        Assert.StartsWith("504", await client.SendAsync("MFF modify=20200102030405;UNIX.mode=0644; /file.txt"));

        // All or nothing: the modify fact was not applied either.
        Assert.NotEqual(2020, fileSystem.GetLastWriteTime("/file.txt").Year);
        Assert.Equal(0, fileSystem.InternalPathRequests);
    }

    [Fact]
    public async Task A_remote_tree_mounted_inside_a_local_one_is_found_per_path()
    {
        var fileSystem = new RemoteMemoryFileSystem();
        await using var server = await StartAsync(fileSystem, mounted: true);
        await using var client = await LoginAsync(server);

        // The provider gets the path inside itself, not the one the client named.
        Assert.Equal("250 DEADBEEF\r\n", await client.SendAsync("XCRC /remote/file.txt"));
        Assert.Equal(("/file.txt", "CRC32", 0L, 5L), fileSystem.LastChecksum);
        Assert.Equal("213 12345\r\n", await client.SendAsync("AVBL /remote"));

        var (_, control) = await client.DownloadAsync("MLSD /remote");
        Assert.Contains("226", control);
        Assert.DoesNotMatch("^2", await client.SendAsync("SITE SYMLINK /remote/file.txt /remote/link.txt"));
        Assert.StartsWith("504", await client.SendAsync("MFF UNIX.mode=0644; /remote/file.txt"));
        Assert.Equal(0, fileSystem.InternalPathRequests);
    }

    [Fact]
    public async Task Paths_a_file_system_reports_read_only_are_refused_up_front_and_listed_without_write()
    {
        var fileSystem = new RemoteMemoryFileSystem { ReadOnlyDirectory = "/locked" };
        await using var server = await StartAsync(fileSystem, mounted: true);
        await using var client = await LoginAsync(server);

        // Refused before a data connection is asked for, not after a 150.
        Assert.StartsWith("550", await client.SendAsync("STOR /remote/locked/new.txt"));
        Assert.StartsWith("550", await client.SendAsync("DELE /remote/locked/file.txt"));
        Assert.True(fileSystem.FileExists("/locked/file.txt"));

        var (locked, _) = await client.DownloadAsync("MLSD /remote/locked");
        var (open, _) = await client.DownloadAsync("MLSD /remote");

        Assert.Matches(@"perm=r;[^\r\n]* file\.txt", Encoding.UTF8.GetString(locked));
        Assert.Matches(@"perm=rawdf;[^\r\n]* file\.txt", Encoding.UTF8.GetString(open));
    }

    private static Task<FtpServerFixture> StartAsync(RemoteMemoryFileSystem fileSystem, bool mounted = false) =>
        FtpServerFixture.StartAsync(
            o => o.Authentication.AllowAnonymous = false,
            services => services.AddSingleton<IFtpAuthenticator>(new RemoteAuthenticator(fileSystem, mounted)));

    private static async Task<FtpTestClient> LoginAsync(FtpServerFixture server)
    {
        var client = await server.ConnectAsync();
        await client.SendAsync("USER remote");
        Assert.StartsWith("230", await client.SendAsync("PASS secret"));
        return client;
    }

    private sealed class RemoteAuthenticator(RemoteMemoryFileSystem fileSystem, bool mounted) : IFtpAuthenticator, IFtpFileSystemSource
    {
        public ValueTask<FtpAuthenticationResult> AuthenticateUserAsync(string userName, System.Net.EndPoint? remoteEndPoint, CancellationToken token) =>
            new(FtpAuthenticationResult.PasswordRequired);

        public ValueTask<FtpAuthenticationResult> AuthenticatePasswordAsync(string userName, string password, System.Net.EndPoint? remoteEndPoint, CancellationToken token) =>
            new(FtpAuthenticationResult.Success(new FtpUser("remote", isAnonymous: false, isReadOnly: false, homeDirectory: null, this)));

        // The session disposes what it is given; the test keeps observing the same instance.
        public IFileSystem Create()
        {
            if (!mounted)
            {
                return new NonDisposingFileSystem(fileSystem);
            }

            var mounts = new MountFileSystem(new MemoryFileSystem(), owned: false);
            mounts.Mount("/remote", fileSystem);
            return mounts;
        }
    }

    private sealed class NonDisposingFileSystem(RemoteMemoryFileSystem inner)
        : ComposeFileSystem(inner, owned: false), IFtpRemoteFileSystem, IFtpChecksumProvider, IFtpAvailableSpaceProvider
    {
        protected override UPath ConvertPathToDelegate(UPath path) => path;

        protected override UPath ConvertPathFromDelegate(UPath path) => path;

        protected override string ConvertPathToInternalImpl(UPath path) => inner.ConvertPathToInternal(path);

        public ValueTask<string?> ComputeChecksumAsync(UPath path, string algorithm, long start, long end, CancellationToken token) =>
            inner.ComputeChecksumAsync(path, algorithm, start, end, token);

        public ValueTask<long?> GetAvailableSpaceAsync(UPath path, CancellationToken token) =>
            inner.GetAvailableSpaceAsync(path, token);
    }

    private sealed class RemoteMemoryFileSystem
        : MemoryFileSystem, IFtpRemoteFileSystem, IFtpChecksumProvider, IFtpAvailableSpaceProvider, IFtpReadOnlyPaths
    {
        public RemoteMemoryFileSystem()
        {
            this.WriteAllText("/file.txt", "hello");
            CreateDirectory("/locked");
            this.WriteAllText("/locked/file.txt", "kept");
        }

        public UPath? ReadOnlyDirectory { get; init; }

        public UPath? UnreadableDirectory { get; init; }

        protected override IEnumerable<FileSystemItem> EnumerateItemsImpl(UPath path, SearchOption searchOption, SearchPredicate? searchPredicate) =>
            path == UnreadableDirectory
                ? throw new IOException("De server is niet bereikbaar.")
                : base.EnumerateItemsImpl(path, searchOption, searchPredicate);

        public string? Digest { get; init; } = "DEADBEEF";

        public (string Path, string Algorithm, long Start, long End)? LastChecksum { get; private set; }

        public int InternalPathRequests { get; private set; }

        protected override string ConvertPathToInternalImpl(UPath path)
        {
            InternalPathRequests++;
            throw new NotSupportedException("There is no host path behind a remote tree.");
        }

        public ValueTask<string?> ComputeChecksumAsync(UPath path, string algorithm, long start, long end, CancellationToken token)
        {
            LastChecksum = (path.FullName, algorithm, start, end);
            return new ValueTask<string?>(Digest);
        }

        public ValueTask<long?> GetAvailableSpaceAsync(UPath path, CancellationToken token) => new(12345L);

        public bool IsReadOnly(UPath path) =>
            ReadOnlyDirectory is { } directory && (path == directory || path.IsInDirectory(directory, recursive: true));
    }
}
