using FtpServer.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer;

/// <summary>
/// Builds and runs the server host.
/// </summary>
public static class ServerRunner
{
    public static async Task<int> RunAsync(string configPath, IReadOnlyList<string> args, CancellationToken token)
    {
        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = [.. args],
        });

        builder.Logging.AddConsole();

        // Later sources win, so this is ordered least to most specific: files, then environment,
        // then the command line.
        //
        // The files are watched: an account added with "FtpServer user add" while the server is
        // running is picked up by the next login, without a restart. Only what a new session reads
        // follows a reload - see FtpOptionsProvider.
        var settings = AddSettingsFile(builder.Configuration, configPath);
        var development = AddSettingsFile(builder.Configuration, DevelopmentVariantOf(configPath));

        builder.Configuration.AddEnvironmentVariables("FTP_");
        builder.Configuration.AddCommandLine([.. args]);

        builder.Services.AddFtpServer();

        builder.Services.AddOptions<FtpOptions>()
            .Bind(builder.Configuration);

        var app = builder.Build();

        // Only now, with the first load behind us, does a broken file become something to survive
        // rather than something to refuse: at startup it means the operator ran the server against
        // a file that does not parse, and at runtime it means an editor saved a half-written one.
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(ServerRunner).FullName!);

        settings.Started(logger);
        development.Started(logger);

        await app.RunAsync(token).ConfigureAwait(false);

        return 0;
    }

    /// <summary>Absolute path of the settings file the CLI reads and writes by default.</summary>
    public static string DefaultConfigPath => Path.Combine(AppContext.BaseDirectory, "appsettings.json");

    private static string DevelopmentVariantOf(string configPath)
    {
        var directory = Path.GetDirectoryName(configPath) ?? string.Empty;
        var name = Path.GetFileNameWithoutExtension(configPath);
        var extension = Path.GetExtension(configPath);

        return Path.Combine(directory, $"{name}.Development{extension}");
    }

    private static WatchedSettingsFile AddSettingsFile(IConfigurationBuilder configuration, string path)
    {
        var watched = new WatchedSettingsFile(path);

        configuration.Add<ResilientJsonConfigurationSource>(source =>
        {
            source.Path = Path.GetFullPath(path);
            source.Optional = true;
            source.ReloadOnChange = true;
            source.OnLoadException = watched.OnLoadException;

            // Without this the path is looked up under the content root, so an absolute --config
            // silently resolves to nothing and the server starts on its defaults.
            source.ResolveFileProvider();
        });

        return watched;
    }

    /// <summary>
    /// Keeps a reload that cannot be parsed from taking the server down.
    /// </summary>
    /// <remarks>
    /// The configuration system raises the parse failure on the file watcher's thread, where an
    /// unhandled exception ends the process - so a stray keystroke in an editor would stop a
    /// running server. Before the host has started there is nothing to protect, and a file that
    /// does not parse is exactly what the operator needs to be told about, so it is left to throw.
    /// </remarks>
    private sealed class WatchedSettingsFile(string path)
    {
        private volatile ILogger? _logger;

        public void Started(ILogger logger) => _logger = logger;

        public void OnLoadException(FileLoadExceptionContext context)
        {
            if (_logger is not { } logger)
            {
                return;
            }

            context.Ignore = true;

            // Ignoring the exception is not enough on its own: the provider has already emptied
            // itself by this point, and an empty settings file means no users, no configured root
            // and a server that turns away everyone until it is restarted.
            (context.Provider as ResilientJsonConfigurationProvider)?.RestoreLastGood();

            Log.SettingsFileUnreadable(logger, path, context.Exception);
        }
    }

    private sealed class ResilientJsonConfigurationSource : JsonConfigurationSource
    {
        public override IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            EnsureDefaults(builder);
            return new ResilientJsonConfigurationProvider(this);
        }
    }

    /// <summary>
    /// A JSON settings provider that remembers the last file it managed to read.
    /// </summary>
    private sealed class ResilientJsonConfigurationProvider(JsonConfigurationSource source)
        : JsonConfigurationProvider(source)
    {
        private Dictionary<string, string?> _lastGood = new(StringComparer.OrdinalIgnoreCase);

        public override void Load(Stream stream)
        {
            base.Load(stream);

            _lastGood = new Dictionary<string, string?>(Data, StringComparer.OrdinalIgnoreCase);
        }

        public void RestoreLastGood() =>
            Data = new Dictionary<string, string?>(_lastGood, StringComparer.OrdinalIgnoreCase);
    }
}
