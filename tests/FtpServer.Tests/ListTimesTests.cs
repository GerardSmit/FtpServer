using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace FtpServer.Tests;

/// <summary>LIST -T (complete timestamps) and the zone LIST times are written in.</summary>
public class ListTimesTests
{
    private static readonly Regex Complete = new(@" [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \d{4} ", RegexOptions.CultureInvariant);

    [Theory]
    [InlineData("LIST -T")]
    [InlineData("LIST -RT")]
    [InlineData("LIST -lT")]
    [InlineData("LIST -R -T")]
    public async Task List_with_t_gives_seconds_and_year(string command)
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("a.txt", "x");

        await using var client = await server.LoginAsync();
        var (data, _) = await client.DownloadAsync(command);

        Assert.Matches(Complete, Encoding.UTF8.GetString(data));
    }

    [Fact]
    public async Task List_without_t_keeps_the_ls_format()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("a.txt", "x");

        await using var client = await server.LoginAsync();
        var (data, _) = await client.DownloadAsync("LIST");

        Assert.DoesNotMatch(Complete, Encoding.UTF8.GetString(data));
    }

    [Fact]
    public async Task List_times_are_written_in_the_configured_zone()
    {
        await using var server = await FtpServerFixture.StartAsync(o => o.List.TimeZone = "UTC");
        var path = server.WriteFile("a.txt", "x");

        await using var client = await server.LoginAsync();
        var (data, _) = await client.DownloadAsync("LIST -T");

        var utc = File.GetLastWriteTimeUtc(path).ToString("MMM dd HH:mm:ss yyyy", CultureInfo.InvariantCulture);
        Assert.Contains($" {utc} a.txt", Encoding.UTF8.GetString(data), StringComparison.Ordinal);
    }
}
