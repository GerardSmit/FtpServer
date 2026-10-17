using System.Diagnostics;
using System.Text;
using FtpServer.IO;

namespace FtpServer.Tests;

/// <summary>
/// Covers the root containment the server documents: a pathname that stays inside the tree as a
/// string, but whose target does not.
/// </summary>
public class ContainmentTests
{
    /// <summary>
    /// Creates a directory link without needing privileges: a junction on Windows, a symbolic
    /// link elsewhere.
    /// </summary>
    private static bool TryCreateDirectoryLink(string linkPath, string targetPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }

        // Junctions need no developer mode and no elevation, unlike a symbolic link.
        var process = Process.Start(new ProcessStartInfo("cmd.exe", ["/c", "mklink", "/J", linkPath, targetPath])
        {
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });

        if (process is null)
        {
            return false;
        }

        process.WaitForExit(TimeSpan.FromSeconds(30));
        return process.ExitCode == 0 && Directory.Exists(linkPath);
    }

    private sealed record Escape(string LinkPath, string Outside, string SecretPath) : IDisposable
    {
        public void Dispose()
        {
            // The link goes first: a recursive delete of the root would walk through the junction
            // and take the target's contents with it.
            RemoveLink(LinkPath);

            try
            {
                Directory.Delete(Outside, recursive: true);
            }
            catch (IOException)
            {
                // Left for the OS to clean up.
            }
        }
    }

    private static void RemoveLink(string linkPath)
    {
        try
        {
            Directory.Delete(linkPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            // Already gone.
        }
    }

    /// <summary>Plants "escape" inside the served root, pointing at a directory outside it.</summary>
    private static Escape? PlantEscape(FtpServerFixture server)
    {
        var outside = Path.Combine(Path.GetTempPath(), "ftpescape-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(outside);

        var secret = Path.Combine(outside, "secret.txt");
        File.WriteAllText(secret, "outside the root");

        var link = Path.Combine(server.Root, "escape");

        if (TryCreateDirectoryLink(link, outside))
        {
            return new Escape(link, outside, secret);
        }

        Directory.Delete(outside, recursive: true);
        return null;
    }

    [Fact]
    public async Task Link_out_of_the_root_is_refused_for_every_operation()
    {
        await using var server = await FtpServerFixture.StartAsync();

        using var escape = PlantEscape(server);

        if (escape is null)
        {
            // No way to make a link on this machine; nothing to prove.
            return;
        }

        await using var client = await server.LoginAsync();

        // Both are refused before a data connection is opened, so no transfer helper is needed.
        Assert.StartsWith("550", await client.SendAsync("RETR escape/secret.txt"));
        Assert.StartsWith("550", await client.SendAsync("STOR escape/created.txt"));
        Assert.False(File.Exists(Path.Combine(escape.Outside, "created.txt")));

        // Metadata, traversal and deletion.
        Assert.StartsWith("550", await client.SendAsync("SIZE escape/secret.txt"));
        Assert.StartsWith("550", await client.SendAsync("MDTM escape/secret.txt"));
        Assert.StartsWith("550", await client.SendAsync("CWD escape"));
        Assert.StartsWith("550", await client.SendAsync("DELE escape/secret.txt"));
        Assert.StartsWith("550", await client.SendAsync("MKD escape/created"));

        // Both ends of a rename, since only one of them is checked by a naive implementation.
        Assert.StartsWith("550", await client.SendAsync("RNFR escape/secret.txt"));

        server.WriteFile("inside.txt", "inside");
        Assert.StartsWith("350", await client.SendAsync("RNFR inside.txt"));
        Assert.StartsWith("550", await client.SendAsync("RNTO escape/moved.txt"));

        Assert.True(File.Exists(escape.SecretPath), "the file outside the root must still be there");
        Assert.False(File.Exists(Path.Combine(escape.Outside, "moved.txt")));
    }

    [Fact]
    public async Task Link_out_of_the_root_is_followed_when_the_option_says_so()
    {
        await using var server = await FtpServerFixture.StartAsync(options => options.FollowLinks = true);

        using var escape = PlantEscape(server);

        if (escape is null)
        {
            return;
        }

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        var (data, control) = await client.DownloadAsync("RETR escape/secret.txt");

        Assert.Equal("outside the root", Encoding.ASCII.GetString(data));
        Assert.Contains("226", control, StringComparison.Ordinal);
    }

    [Fact]
    public void Resolution_follows_a_link_half_way_up_a_path()
    {
        var outside = Path.Combine(Path.GetTempPath(), "ftpescape-" + Guid.NewGuid().ToString("N")[..8]);
        var root = Path.Combine(Path.GetTempPath(), "ftproot-" + Guid.NewGuid().ToString("N")[..8]);

        Directory.CreateDirectory(Path.Combine(outside, "deep"));
        Directory.CreateDirectory(root);

        try
        {
            if (!TryCreateDirectoryLink(Path.Combine(root, "link"), outside))
            {
                return;
            }

            // The link is not the last component, which resolving only the leaf would miss.
            var resolved = NoFollowPhysicalFileSystem.ResolveLinks(Path.Combine(root, "link", "deep", "file.txt"));

            Assert.StartsWith(outside, resolved, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            RemoveLink(Path.Combine(root, "link"));

            try
            {
                Directory.Delete(root, recursive: true);
                Directory.Delete(outside, recursive: true);
            }
            catch (IOException)
            {
                // Left for the OS to clean up.
            }
        }
    }

    [Fact]
    public void A_link_is_still_refused_while_its_directory_is_being_enumerated()
    {
        // During an enumeration only the last component of a child is checked, since the
        // directory itself was resolved when the enumeration began. A child that is itself a
        // link must still be resolved in full - and refused when it leads out.
        var outside = Path.Combine(Path.GetTempPath(), "ftpescape-" + Guid.NewGuid().ToString("N")[..8]);
        var root = Path.Combine(Path.GetTempPath(), "ftproot-" + Guid.NewGuid().ToString("N")[..8]);

        Directory.CreateDirectory(outside);
        Directory.CreateDirectory(Path.Combine(root, "plain"));
        File.WriteAllText(Path.Combine(root, "file.txt"), "x");

        try
        {
            if (!TryCreateDirectoryLink(Path.Combine(root, "link"), outside))
            {
                return;
            }

            using var physical = new NoFollowPhysicalFileSystem(root);
            using var fileSystem = new Zio.FileSystems.SubFileSystem(physical, physical.ConvertPathFromInternal(root), owned: false);

            var seen = new List<string>();

            foreach (var item in fileSystem.EnumerateItems(Zio.UPath.Root, SearchOption.TopDirectoryOnly))
            {
                var name = item.GetName();
                seen.Add(name);

                if (name == "link")
                {
                    Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal(item.Path));
                }
                else
                {
                    Assert.Equal(Path.Combine(root, name), fileSystem.ConvertPathToInternal(item.Path), ignoreCase: true);
                }

                // A path below the link is not a child of the enumerated directory.
                Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal("/link/inner.txt"));
            }

            Assert.Equal(["file.txt", "link", "plain"], seen.Order());

            // And nothing of the shortcut outlives the enumeration.
            Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal("/link"));
        }
        finally
        {
            RemoveLink(Path.Combine(root, "link"));

            try
            {
                Directory.Delete(root, recursive: true);
                Directory.Delete(outside, recursive: true);
            }
            catch (IOException)
            {
                // Left for the OS to clean up.
            }
        }
    }

    /// <summary>Scratch directories for the tests that drive the file system directly.</summary>
    private sealed class Scratch : IDisposable
    {
        private readonly List<string> _links = [];
        private readonly List<string> _directories = [];

        public string Directory(string prefix)
        {
            var path = Path.Combine(Path.GetTempPath(), prefix + "-" + Guid.NewGuid().ToString("N")[..8]);
            System.IO.Directory.CreateDirectory(path);
            _directories.Add(path);
            return path;
        }

        public bool Link(string linkPath, string targetPath)
        {
            _links.Add(linkPath);
            return TryCreateDirectoryLink(linkPath, targetPath);
        }

        public void Dispose()
        {
            // Links first, so a recursive delete never walks through one into its target.
            foreach (var link in _links)
            {
                RemoveLink(link);
            }

            foreach (var directory in _directories)
            {
                try
                {
                    System.IO.Directory.Delete(directory, recursive: true);
                }
                catch (IOException)
                {
                    // Left for the OS to clean up.
                }
            }
        }
    }

    private static Zio.FileSystems.SubFileSystem Jail(NoFollowPhysicalFileSystem physical, string root) =>
        new(physical, physical.ConvertPathFromInternal(root), owned: true);

    [Fact]
    public void A_root_reached_through_a_link_still_confines_what_is_below_it()
    {
        // Only the components below the root are walked per operation, starting from where the
        // root lands - so a root that is itself a link must still map onto its target correctly.
        using var scratch = new Scratch();
        var real = scratch.Directory("ftpreal");
        var outside = scratch.Directory("ftpescape");
        var parent = scratch.Directory("ftplinks");
        File.WriteAllText(Path.Combine(real, "file.txt"), "x");

        var root = Path.Combine(parent, "root");

        if (!scratch.Link(root, real) || !scratch.Link(Path.Combine(real, "out"), outside))
        {
            return;
        }

        using var fileSystem = Jail(new NoFollowPhysicalFileSystem(root), root);

        Assert.True(fileSystem.FileExists("/file.txt"));
        Assert.Equal(Path.Combine(root, "file.txt"), fileSystem.ConvertPathToInternal("/file.txt"), ignoreCase: true);
        Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal("/out"));
        Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal("/out/secret.txt"));
    }

    [Fact]
    public void A_link_chain_is_judged_by_where_it_finally_lands()
    {
        // "out" leaves the tree and "back" returns into it. The walk restarts at each target, and
        // a target back inside the root restarts from the root rather than the volume.
        using var scratch = new Scratch();
        var root = scratch.Directory("ftproot");
        var outside = scratch.Directory("ftpescape");
        System.IO.Directory.CreateDirectory(Path.Combine(root, "sub"));
        System.IO.Directory.CreateDirectory(Path.Combine(outside, "stays"));

        if (!scratch.Link(Path.Combine(root, "out"), outside) ||
            !scratch.Link(Path.Combine(outside, "back"), Path.Combine(root, "sub")))
        {
            return;
        }

        using var fileSystem = Jail(new NoFollowPhysicalFileSystem(root), root);

        Assert.Equal(Path.Combine(root, "out", "back", "f.txt"), fileSystem.ConvertPathToInternal("/out/back/f.txt"), ignoreCase: true);
        Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal("/out/stays/f.txt"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(200)]
    public async Task A_root_swapped_for_a_link_is_refused_once_it_is_rechecked(int recheckMilliseconds)
    {
        // The root's own resolution is trusted for a short while instead of being walked on every
        // operation. Once it is re-resolved, a root that now lands elsewhere refuses everything.
        using var scratch = new Scratch();
        var parent = scratch.Directory("ftpswap");
        var outside = scratch.Directory("ftpescape");
        var root = Path.Combine(parent, "root");
        System.IO.Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "file.txt"), "inside");
        File.WriteAllText(Path.Combine(outside, "file.txt"), "outside");

        using var fileSystem = Jail(new NoFollowPhysicalFileSystem(root, TimeSpan.FromMilliseconds(recheckMilliseconds)), root);

        Assert.True(fileSystem.FileExists("/file.txt"));

        // Swap the root for a junction to a directory outside it.
        System.IO.Directory.Move(root, Path.Combine(parent, "moved"));

        if (!scratch.Link(root, outside))
        {
            return;
        }

        await Task.Delay(recheckMilliseconds * 2);

        Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal("/file.txt"));
        Assert.Throws<UnauthorizedAccessException>(() => fileSystem.ConvertPathToInternal("/"));
    }

    [Fact]
    public async Task Dangling_link_out_of_the_root_is_refused_for_creation()
    {
        await using var server = await FtpServerFixture.StartAsync();

        // The target does not exist, so an existence check alone would see nothing at the link
        // and wave the path through - after which STOR or MKD would create the target.
        var outside = Path.Combine(Path.GetTempPath(), "ftpdangling-" + Guid.NewGuid().ToString("N")[..8]);
        var link = Path.Combine(server.Root, "dangling");

        Directory.CreateDirectory(outside);

        try
        {
            if (!TryCreateDirectoryLink(link, outside))
            {
                return;
            }

            Directory.Delete(outside);

            await using var client = await server.LoginAsync();

            Assert.StartsWith("550", await client.SendAsync("STOR dangling/created.txt"));
            Assert.StartsWith("550", await client.SendAsync("MKD dangling/created"));
            Assert.False(Directory.Exists(outside), "nothing may be created outside the root");
        }
        finally
        {
            RemoveLink(link);

            if (Directory.Exists(outside))
            {
                Directory.Delete(outside, recursive: true);
            }
        }
    }

    [Fact]
    public void A_path_with_no_links_resolves_to_itself()
    {
        var root = Path.Combine(Path.GetTempPath(), "ftproot-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(root, "sub"));

        try
        {
            var path = Path.Combine(root, "sub", "does-not-exist-yet.txt");

            // A file that does not exist yet still has to resolve, or a STOR could not be checked.
            Assert.Equal(path, NoFollowPhysicalFileSystem.ResolveLinks(path));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
