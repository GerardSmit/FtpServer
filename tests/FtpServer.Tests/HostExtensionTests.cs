using FtpServer.Handlers;
using Microsoft.Extensions.DependencyInjection;

namespace FtpServer.Tests;

/// <summary>SITE sub-commands and FEAT lines a host adds through the service collection.</summary>
public class HostExtensionTests
{
    private sealed class EchoCommand : IFtpSiteCommand
    {
        public string Name => "ECHO";

        public ValueTask ExecuteAsync(FtpSession session, string argument, CancellationToken token) =>
            session.WriteAsync($"200 {argument}\r\n", token);
    }

    private sealed class SwitchedCommand : IFtpSiteCommand
    {
        public static bool On { get; set; }

        public string Name => "SWITCHED";

        public bool IsAvailable(FtpSession session) => On;

        public ValueTask ExecuteAsync(FtpSession session, string argument, CancellationToken token) =>
            session.WriteAsync("200 on\r\n", token);
    }

    private sealed class LoggedInFeature : IFtpFeatureProvider
    {
        public IEnumerable<string> GetFeatures(FtpSession session) =>
            session.IsAuthenticated ? ["ECHO"] : [];
    }

    private static Task<FtpServerFixture> StartAsync() => FtpServerFixture.StartAsync(configureServices: services =>
    {
        services.AddSingleton<IFtpSiteCommand, EchoCommand>();
        services.AddSingleton<IFtpSiteCommand, SwitchedCommand>();
        services.AddSingleton<IFtpFeatureProvider, LoggedInFeature>();
    });

    [Fact]
    public async Task A_host_site_command_answers_and_is_listed()
    {
        await using var server = await StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("200 hello there", await client.SendAsync("SITE echo hello there"));
        Assert.Contains("ECHO", await client.SendAsync("SITE HELP"), StringComparison.Ordinal);
        Assert.Contains(" SITE CHMOD;HELP;UTIME;ECHO", await client.SendAsync("FEAT"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_site_command_that_is_switched_off_is_not_listed_nor_run()
    {
        await using var server = await StartAsync();
        await using var client = await server.LoginAsync();

        SwitchedCommand.On = false;

        Assert.Contains(" SITE CHMOD;HELP;UTIME;ECHO\r\n", await client.SendAsync("FEAT"), StringComparison.Ordinal);
        Assert.DoesNotContain("SWITCHED", await client.SendAsync("SITE HELP"), StringComparison.Ordinal);
        Assert.StartsWith("504", await client.SendAsync("SITE SWITCHED"));

        SwitchedCommand.On = true;

        Assert.Contains(" SITE CHMOD;HELP;UTIME;ECHO;SWITCHED\r\n", await client.SendAsync("FEAT"), StringComparison.Ordinal);
        Assert.StartsWith("200 on", await client.SendAsync("SITE SWITCHED"));
    }

    [Fact]
    public async Task A_host_site_command_needs_a_login()
    {
        await using var server = await StartAsync();
        await using var client = await server.ConnectAsync();

        Assert.StartsWith("530", await client.SendAsync("SITE ECHO hello"));
    }

    [Fact]
    public async Task An_unknown_site_command_is_still_refused()
    {
        await using var server = await StartAsync();
        await using var client = await server.LoginAsync();

        Assert.StartsWith("504", await client.SendAsync("SITE NOPE"));
    }

    [Fact]
    public async Task A_host_feature_is_listed_as_its_provider_decides()
    {
        await using var server = await StartAsync();
        await using var client = await server.ConnectAsync();

        Assert.DoesNotContain(" ECHO\r\n", await client.SendAsync("FEAT"), StringComparison.Ordinal);

        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");

        Assert.Contains(" ECHO\r\n", await client.SendAsync("FEAT"), StringComparison.Ordinal);
    }
}
