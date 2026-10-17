using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer;

/// <summary>
/// Checks at startup what would otherwise only be discovered by a client mid-session.
/// </summary>
/// <remarks>
/// Taking <see cref="FtpOptionsProvider"/> is what forces the configuration to be validated here,
/// before the listener binds, rather than on the first connection. Option validation confirms the
/// certificate file exists; <see cref="CertificateProvider.Validate"/> proves it is usable, so a
/// bad one stops the server rather than failing every client's handshake.
/// </remarks>
public sealed class StartupValidationHostedService(
    CertificateProvider provider,
    FtpOptionsProvider options,
    ILogger<StartupValidationHostedService> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (options.Current.Ftps)
        {
            provider.Validate();
        }

        foreach (var user in options.Current.Authentication.Users)
        {
            if (string.IsNullOrEmpty(user.PasswordHash) &&
                (user.Password is not null || !string.IsNullOrEmpty(user.PasswordSha256)))
            {
                Log.WeakPasswordStorage(logger, user.Name);
            }
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
