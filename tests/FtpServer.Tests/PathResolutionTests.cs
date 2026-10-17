using FtpServer.Extensions;
using Zio;

namespace FtpServer.Tests;

public class PathResolutionTests
{
    private static string? Resolve(string argument, string current = "/")
        => SequenceExtensions.TryResolvePath(argument, new UPath(current), out var path) ? path.FullName : null;

    [Theory]
    [InlineData("sub", "/", "/sub")]
    [InlineData("sub", "/base", "/base/sub")]
    [InlineData("/abs", "/base", "/abs")]
    [InlineData("./sub", "/base", "/base/sub")]
    [InlineData("a/b/c", "/", "/a/b/c")]
    [InlineData("a//b", "/", "/a/b")]
    [InlineData("a\\b", "/", "/a/b")]
    public void Resolves_relative_and_absolute_paths(string argument, string current, string expected)
    {
        Assert.Equal(expected, Resolve(argument, current));
    }

    [Theory]
    // Every one of these used to either escape the root or throw and wedge the session.
    [InlineData("..", "/", "/")]
    [InlineData("../..", "/", "/")]
    [InlineData("/../", "/", "/")]
    [InlineData("/../../etc/passwd", "/", "/etc/passwd")]
    [InlineData("..", "/a/b", "/a")]
    [InlineData("../../../../..", "/a/b", "/")]
    [InlineData("a/../../..", "/", "/")]
    [InlineData("....//", "/", null)]
    public void Dot_dot_is_clamped_at_the_root(string argument, string current, string? expected)
    {
        Assert.Equal(expected, Resolve(argument, current));
    }

    [Fact]
    public void Empty_argument_keeps_the_current_directory()
    {
        Assert.Equal("/base", Resolve(string.Empty, "/base"));
    }

    [Fact]
    public void Quoted_pathnames_are_unwrapped()
    {
        Assert.Equal("/quoted name", Resolve("\"quoted name\""));
    }

    [Theory]
    [InlineData("a\0b")]
    [InlineData("a\rb")]
    [InlineData("a\nb")]
    [InlineData("a\tb")]
    public void Control_characters_are_rejected_on_every_platform(string argument)
    {
        // They cannot appear in a listing line without corrupting it.
        Assert.Null(Resolve(argument));
    }

    [Theory]
    [InlineData("a:b")]
    [InlineData("a*b")]
    [InlineData("a?b")]
    [InlineData("a|b")]
    [InlineData("a\"b")]
    [InlineData("trailing.")]
    [InlineData("trailing ")]
    [InlineData("CON")]
    [InlineData("nul.txt")]
    [InlineData("COM1")]
    public void Windows_reserved_names_are_rejected_on_windows(string argument)
    {
        if (!OperatingSystem.IsWindows())
        {
            // These are ordinary filename characters on Unix.
            Assert.NotNull(Resolve(argument));
            return;
        }

        Assert.Null(Resolve(argument));
    }

    [Theory]
    [InlineData("/", "/")]
    [InlineData("/a\"b", "/a\"\"b")]
    public void Quoted_path_doubles_embedded_quotes(string path, string expected)
    {
        // RFC 959 section 4.1.3: a 257 reply doubles any quote inside the pathname.
        Assert.Equal(expected, new UPath(path).ToQuotedPath());
    }
}
