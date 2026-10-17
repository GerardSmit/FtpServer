using FtpServer.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpServer;

/// <summary>
/// The configuration as it stands right now, re-read when the underlying file changes.
/// </summary>
/// <remarks>
/// <para>
/// Two things stand between a saved file and the running server. <see cref="IOptions{T}"/> resolves
/// once for the lifetime of the process, so a component holding one never sees a reload at all;
/// only <see cref="IOptionsMonitor{T}"/> does. And validation attached to the options themselves
/// would throw out of the monitor's own change handler, on the file watcher's thread, where nothing
/// can catch it - which is why <see cref="FtpOptionsValidator"/> is called from here instead.
/// </para>
/// <para>
/// A reload that does not validate is refused and logged, and the previous configuration stays in
/// force. A typo saved at runtime must not stop the server, and must certainly not open it up.
/// </para>
/// <para>
/// Only what a new session reads should be taken from here: the listening port, the passive range
/// and the certificate are bound at startup, and a component that acted on a change to those would
/// disagree with the sockets that are already open.
/// </para>
/// </remarks>
public sealed class FtpOptionsProvider : IDisposable
{
    private readonly IDisposable? _subscription;
    private volatile FtpOptions _current;

    public FtpOptionsProvider(IOptionsMonitor<FtpOptions> monitor, ILogger<FtpOptionsProvider> logger)
    {
        var initial = monitor.CurrentValue;

        // Nothing to fall back on at startup, so an invalid configuration stops the server here.
        // The exception type is the one option validation would have thrown, because that is what
        // a host - and the test suite - expects a bad configuration to look like.
        if (!FtpOptionsValidator.Validate(initial, out var error))
        {
            throw new OptionsValidationException(
                Microsoft.Extensions.Options.Options.DefaultName,
                typeof(FtpOptions),
                [$"Invalid FTP server configuration. {error}"]);
        }

        _current = initial;

        _subscription = monitor.OnChange(updated =>
        {
            if (!FtpOptionsValidator.Validate(updated, out var reloadError))
            {
                Log.ConfigurationReloadRejected(
                    logger,
                    new OptionsValidationException(
                        Microsoft.Extensions.Options.Options.DefaultName,
                        typeof(FtpOptions),
                        [$"Invalid FTP server configuration. {reloadError}"]));

                return;
            }

            _current = updated;
            Log.ConfigurationReloaded(logger);
        });
    }

    /// <summary>The most recent configuration that passed validation.</summary>
    public FtpOptions Current => _current;

    public void Dispose() => _subscription?.Dispose();
}
