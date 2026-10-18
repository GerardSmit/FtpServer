using System.Text;
using FtpServer.Authentication;
using FtpServer.IO;
using FtpServer.Options;
using Microsoft.Extensions.DependencyInjection;
using Zio;
using Zio.FileSystems;

namespace FtpServer.Tests;

/// <summary>
/// Per-user trees: virtual folders from the configuration, and a file system supplied by an
/// authenticator.
/// </summary>
public class VirtualFolderTests
{
    private static async Task<FtpTestClient> LoginAsync(FtpServerFixture server, string user = "alice", string password = "secret")
    {
        var client = await server.ConnectAsync();
        await client.SendAsync($"USER {user}");
        var reply = await client.SendAsync($"PASS {password}");

        Assert.StartsWith("230", reply);
        return client;
    }

    private static string CreateExternalDirectory(out string name)
    {
        name = "ftpext-" + Guid.NewGuid().ToString("N")[..8];
        var path = Path.Combine(Path.GetTempPath(), name);
        Directory.CreateDirectory(path);
        return path;
    }

    [Fact]
    public async Task A_virtual_folder_outside_the_root_is_listed_and_readable()
    {
        var external = CreateExternalDirectory(out _);
        await File.WriteAllTextAsync(Path.Combine(external, "note.txt"), "hello");

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.Authentication.AllowAnonymous = false;
                o.Authentication.Users.Add(new FtpUserOptions
                {
                    Name = "alice",
                    Password = "secret",
                    VirtualFolders =
                    {
                        new FtpVirtualFolderOptions { Path = "/shared", PhysicalPath = external },
                    },
                });
            });

            await using var client = await LoginAsync(server);

            var (listing, _) = await client.DownloadAsync("NLST /");
            Assert.Contains("shared", Encoding.UTF8.GetString(listing));

            var (contents, control) = await client.DownloadAsync("RETR /shared/note.txt");

            Assert.Contains("226", control);
            Assert.Equal("hello", Encoding.UTF8.GetString(contents));
        }
        finally
        {
            Directory.Delete(external, recursive: true);
        }
    }

    [Fact]
    public async Task A_virtual_folder_does_not_hide_the_home_directory()
    {
        var external = CreateExternalDirectory(out _);

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.Authentication.AllowAnonymous = false;
                o.Authentication.Users.Add(new FtpUserOptions
                {
                    Name = "alice",
                    Password = "secret",
                    HomeDirectory = "alice",
                    VirtualFolders =
                    {
                        new FtpVirtualFolderOptions { Path = "/shared", PhysicalPath = external },
                    },
                });
            });

            Directory.CreateDirectory(Path.Combine(server.Root, "alice"));
            await File.WriteAllTextAsync(Path.Combine(server.Root, "alice", "own.txt"), "mine");

            await using var client = await LoginAsync(server);

            var (listing, _) = await client.DownloadAsync("NLST /");
            var text = Encoding.UTF8.GetString(listing);

            Assert.Contains("own.txt", text);
            Assert.Contains("shared", text);
        }
        finally
        {
            Directory.Delete(external, recursive: true);
        }
    }

    [Fact]
    public async Task A_read_only_virtual_folder_refuses_writes_while_the_rest_of_the_tree_accepts_them()
    {
        var external = CreateExternalDirectory(out _);
        await File.WriteAllTextAsync(Path.Combine(external, "note.txt"), "hello");

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.Authentication.AllowAnonymous = false;
                o.Authentication.Users.Add(new FtpUserOptions
                {
                    Name = "alice",
                    Password = "secret",
                    VirtualFolders =
                    {
                        new FtpVirtualFolderOptions { Path = "/archive", PhysicalPath = external, ReadOnly = true },
                    },
                });
            });

            await using var client = await LoginAsync(server);

            // Refused outright, not after a 150: the transfer never starts.
            Assert.StartsWith("550", await client.SendAsync("STOR /archive/new.txt"));
            Assert.StartsWith("550", await client.SendAsync("DELE /archive/note.txt"));
            Assert.StartsWith("550", await client.SendAsync("MKD /archive/sub"));

            // Refused at RNFR: a rename out of a read-only folder deletes from it.
            Assert.StartsWith("550", await client.SendAsync("RNFR /archive/note.txt"));

            Assert.True(File.Exists(Path.Combine(external, "note.txt")));

            // Listings say so too, rather than advertising writes that are then refused.
            var (archive, _) = await client.DownloadAsync("MLSD /archive");
            Assert.Matches(@"perm=[^;w]*;[^\r\n]* note\.txt", Encoding.UTF8.GetString(archive));

            // The same session can still write outside the mount.
            Assert.Contains("226", await client.UploadAsync("STOR /own.txt", "mine"u8.ToArray()));
        }
        finally
        {
            Directory.Delete(external, recursive: true);
        }
    }

    [Fact]
    public async Task A_read_only_folder_cannot_be_escaped_by_renaming_into_it()
    {
        var external = CreateExternalDirectory(out _);

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.Authentication.AllowAnonymous = false;
                o.Authentication.Users.Add(new FtpUserOptions
                {
                    Name = "alice",
                    Password = "secret",
                    VirtualFolders =
                    {
                        new FtpVirtualFolderOptions { Path = "/archive", PhysicalPath = external, ReadOnly = true },
                    },
                });
            });

            await using var client = await LoginAsync(server);

            await client.UploadAsync("STOR /own.txt", "mine"u8.ToArray());
            await client.SendAsync("RNFR /own.txt");

            Assert.StartsWith("550", await client.SendAsync("RNTO /archive/own.txt"));
            Assert.False(File.Exists(Path.Combine(external, "own.txt")));
        }
        finally
        {
            Directory.Delete(external, recursive: true);
        }
    }

    [Fact]
    public async Task An_authenticator_can_supply_the_file_system_for_a_user()
    {
        await using var server = await FtpServerFixture.StartAsync(
            o => o.Authentication.AllowAnonymous = false,
            services => services.AddSingleton<IFtpAuthenticator, MemoryFileSystemAuthenticator>());

        await using var client = await LoginAsync(server, "memory", "anything");

        var (listing, _) = await client.DownloadAsync("NLST /");
        Assert.Contains("in-memory.txt", Encoding.UTF8.GetString(listing));

        var (contents, control) = await client.DownloadAsync("RETR /in-memory.txt");

        Assert.Contains("226", control);
        Assert.Equal("served from memory", Encoding.UTF8.GetString(contents));
    }

    [Fact]
    public async Task A_user_without_virtual_folders_still_gets_a_plain_home_directory()
    {
        await using var server = await FtpServerFixture.StartAsync(o =>
        {
            o.Authentication.AllowAnonymous = false;
            o.Authentication.Users.Add(new FtpUserOptions
            {
                Name = "alice",
                Password = "secret",
                HomeDirectory = "alice",
            });
        });

        Directory.CreateDirectory(Path.Combine(server.Root, "alice"));
        await File.WriteAllTextAsync(Path.Combine(server.Root, "alice", "own.txt"), "mine");
        await File.WriteAllTextAsync(Path.Combine(server.Root, "outside.txt"), "not mine");

        await using var client = await LoginAsync(server);

        var (listing, _) = await client.DownloadAsync("NLST /");
        var text = Encoding.UTF8.GetString(listing);

        Assert.Contains("own.txt", text);
        Assert.DoesNotContain("outside.txt", text);
    }

    [Fact]
    public async Task A_server_wide_virtual_folder_is_served_to_every_session()
    {
        var external = CreateExternalDirectory(out _);
        await File.WriteAllTextAsync(Path.Combine(external, "note.txt"), "for everyone");

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.VirtualFolders.Add(new FtpVirtualFolderOptions { Path = "/public", PhysicalPath = external });

                // A named user with a home of their own, and the anonymous login the fixture
                // enables: both have to see it.
                o.Authentication.Users.Add(new FtpUserOptions
                {
                    Name = "alice",
                    Password = "secret",
                    HomeDirectory = "alice",
                });
            });

            await using (var named = await LoginAsync(server))
            {
                var (contents, control) = await named.DownloadAsync("RETR /public/note.txt");

                Assert.Contains("226", control);
                Assert.Equal("for everyone", Encoding.UTF8.GetString(contents));
            }

            await using var anonymous = await server.LoginAsync();

            var (listing, _) = await anonymous.DownloadAsync("NLST /");
            Assert.Contains("public", Encoding.UTF8.GetString(listing));
        }
        finally
        {
            Directory.Delete(external, recursive: true);
        }
    }

    [Fact]
    public async Task A_user_folder_replaces_the_server_wide_one_on_the_same_path()
    {
        var shared = CreateExternalDirectory(out _);
        var mine = CreateExternalDirectory(out _);

        await File.WriteAllTextAsync(Path.Combine(shared, "everyones.txt"), "shared");
        await File.WriteAllTextAsync(Path.Combine(mine, "alices.txt"), "hers");

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.Authentication.AllowAnonymous = false;
                o.VirtualFolders.Add(new FtpVirtualFolderOptions { Path = "/data", PhysicalPath = shared });

                o.Authentication.Users.Add(new FtpUserOptions
                {
                    Name = "alice",
                    Password = "secret",
                    VirtualFolders =
                    {
                        new FtpVirtualFolderOptions { Path = "/data", PhysicalPath = mine },
                    },
                });
            });

            await using var client = await LoginAsync(server);

            var (listing, _) = await client.DownloadAsync("NLST /data");
            var text = Encoding.UTF8.GetString(listing);

            Assert.Contains("alices.txt", text);
            Assert.DoesNotContain("everyones.txt", text);
        }
        finally
        {
            Directory.Delete(shared, recursive: true);
            Directory.Delete(mine, recursive: true);
        }
    }

    [Fact]
    public async Task A_server_wide_folder_and_a_user_folder_are_served_side_by_side()
    {
        var shared = CreateExternalDirectory(out _);
        var mine = CreateExternalDirectory(out _);

        try
        {
            await using var server = await FtpServerFixture.StartAsync(o =>
            {
                o.Authentication.AllowAnonymous = false;
                o.VirtualFolders.Add(new FtpVirtualFolderOptions { Path = "/public", PhysicalPath = shared, ReadOnly = true });

                o.Authentication.Users.Add(new FtpUserOptions
                {
                    Name = "alice",
                    Password = "secret",
                    VirtualFolders =
                    {
                        new FtpVirtualFolderOptions { Path = "/mine", PhysicalPath = mine },
                    },
                });
            });

            await using var client = await LoginAsync(server);

            var (listing, _) = await client.DownloadAsync("NLST /");
            var text = Encoding.UTF8.GetString(listing);

            Assert.Contains("public", text);
            Assert.Contains("mine", text);

            // The server-wide folder keeps its own access, next to a writable per-user one.
            Assert.StartsWith("550", await client.SendAsync("STOR /public/new.txt"));
            Assert.Contains("226", await client.UploadAsync("STOR /mine/new.txt", "ok"u8.ToArray()));
        }
        finally
        {
            Directory.Delete(shared, recursive: true);
            Directory.Delete(mine, recursive: true);
        }
    }

    /// <summary>
    /// Serves one user out of a memory file system, which is what an authenticator backed by
    /// something other than the configuration would do.
    /// </summary>
    private sealed class MemoryFileSystemAuthenticator : IFtpAuthenticator
    {
        public ValueTask<FtpAuthenticationResult> AuthenticateUserAsync(string userName, System.Net.EndPoint? remoteEndPoint, CancellationToken token) =>
            new(FtpAuthenticationResult.PasswordRequired);

        public ValueTask<FtpAuthenticationResult> AuthenticatePasswordAsync(string userName, string password, System.Net.EndPoint? remoteEndPoint, CancellationToken token)
        {
            if (!string.Equals(userName, "memory", StringComparison.Ordinal))
            {
                return new ValueTask<FtpAuthenticationResult>(FtpAuthenticationResult.Failed);
            }

            var user = new FtpUser("memory", isAnonymous: false, isReadOnly: false, homeDirectory: null, new MemorySource());

            return new ValueTask<FtpAuthenticationResult>(FtpAuthenticationResult.Success(user));
        }

        private sealed class MemorySource : IFtpFileSystemSource
        {
            public IFileSystem Create()
            {
                var fileSystem = new MemoryFileSystem();
                fileSystem.WriteAllText("/in-memory.txt", "served from memory");
                return fileSystem;
            }
        }
    }
}
