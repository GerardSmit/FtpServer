using FtpServer.Authentication;
using FtpServer.Configuration;
using FtpServer.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer.Tests;

/// <summary>
/// Configuration that is re-read while the server runs: a user added with the CLI has to be able
/// to log in without a restart, and a file that stops making sense must not take the server with
/// it.
/// </summary>
public class ConfigurationReloadTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "ftpreload-" + Guid.NewGuid().ToString("N")[..8]);

    private string ConfigPath => Path.Combine(_directory, "appsettings.json");

    /// <summary>
    /// Writes the settings file the way the CLI does - completely, then into place.
    /// </summary>
    /// <remarks>
    /// Not a detail: the file is being watched, and a plain write is visible to the watcher while
    /// it is still half a file. The configuration provider raises that parse failure on the
    /// watcher's own thread, where nothing catches it and the process ends. The server guards
    /// against a third party doing this (see ServerRunner); a test must not do it itself.
    /// </remarks>
    private void WriteConfig(string json)
    {
        Directory.CreateDirectory(_directory);

        var temporary = ConfigPath + ".tmp";
        File.WriteAllText(temporary, json);
        File.Move(temporary, ConfigPath, overwrite: true);
    }

    private readonly List<IHost> _hosts = [];

    public void Dispose()
    {
        // Every host first, then the directory. A host that is still alive is still watching this
        // directory, and deleting a watched directory raises an error on the watcher's own thread
        // - which ends the test process rather than failing a test.
        foreach (var host in _hosts)
        {
            host.Dispose();
        }

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Temporary directory; the OS will get to it.
        }

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Builds the options pipeline the server uses - a watched JSON file, bound and validated -
    /// without opening a socket. The host is disposed with the test, however it ends.
    /// </summary>
    private IHost BuildHost()
    {
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Logging.SetMinimumLevel(LogLevel.None);

        builder.Configuration.AddJsonFile(ConfigPath, optional: true, reloadOnChange: true);

        builder.Services.AddFtpServerCore();
        builder.Services.AddOptions<FtpOptions>().Bind(builder.Configuration);

        var host = builder.Build();
        _hosts.Add(host);

        return host;
    }

    private (FtpOptionsProvider Options, IFtpAuthenticator Authenticator) Build()
    {
        var services = BuildHost().Services;

        return (services.GetRequiredService<FtpOptionsProvider>(), services.GetRequiredService<IFtpAuthenticator>());
    }

    /// <summary>
    /// Waits for the file watcher, which is not instantaneous and not on this thread.
    /// </summary>
    private static async Task<bool> WaitForAsync(Func<bool> condition, int timeoutMs = 10000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);

        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(100);
        }

        return condition();
    }

    [Fact]
    public async Task A_user_added_while_the_server_runs_can_log_in()
    {
        // The wait below retries a login that is refused until the reload lands; the per-user
        // lockout would otherwise count those retries.
        WriteConfig("""{ "Path": "ftproot", "Authentication": { "MaxFailedAttempts": 0, "Users": [] } }""");

        var (_, authenticator) = Build();

        Assert.Equal(
            FtpAuthenticationStatus.Failed,
            (await authenticator.AuthenticatePasswordAsync("alice", "secret", null, TestContext.Current.CancellationToken)).Status);

        var file = UserConfigurationFile.Load(ConfigPath);
        file.Add("alice", PasswordHash.Create("secret", iterations: 1000), null, readOnly: false);
        file.Save();

        var loggedIn = await WaitForAsync(() =>
            authenticator.AuthenticatePasswordAsync("alice", "secret", null, CancellationToken.None)
                .AsTask().GetAwaiter().GetResult().Status == FtpAuthenticationStatus.Success);

        Assert.True(loggedIn, "the account added while running should authenticate without a restart");
    }

    [Fact]
    public async Task An_invalid_reload_is_refused_and_the_previous_configuration_stays_in_force()
    {
        WriteConfig("""{ "Port": 2121, "Path": "ftproot", "Authentication": { "Users": [] } }""");

        var (options, _) = Build();

        Assert.Equal(2121, options.Current.Port);

        // Out of range, so validation refuses it - the reload must be dropped rather than leaving
        // the server with a port it cannot serve.
        WriteConfig("""{ "Port": 99999, "Path": "ftproot", "Authentication": { "Users": [] } }""");

        // Give the watcher long enough to have applied it, had it been going to.
        await Task.Delay(2000);

        Assert.Equal(2121, options.Current.Port);
    }

    [Fact]
    public async Task A_valid_reload_is_applied()
    {
        WriteConfig("""{ "Port": 2121, "Path": "ftproot", "Authentication": { "MaxFailedAttempts": 5, "Users": [] } }""");

        var (options, _) = Build();

        WriteConfig("""{ "Port": 2121, "Path": "ftproot", "Authentication": { "MaxFailedAttempts": 9, "Users": [] } }""");

        Assert.True(await WaitForAsync(() => options.Current.Authentication.MaxFailedAttempts == 9));
    }

    [Fact]
    public void An_invalid_configuration_stops_the_server_at_startup()
    {
        WriteConfig("""{ "Port": 99999 }""");

        Assert.Throws<OptionsValidationException>(() => Build());
    }
}
