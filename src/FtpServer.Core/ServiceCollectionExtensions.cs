using FtpServer.Authentication;
using FtpServer.Handlers;
using FtpServer.IO;
using FtpServer.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace FtpServer;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddFtpServerCore(this IServiceCollection services, Action<FtpOptions>? configureOptions = null)
    {
        services.TryAddSingleton<FtpConnectionHandler>();
        services.TryAddSingleton<FtpOptionsProvider>();
        services.TryAddSingleton<FtpFileSystemFactory>();
        services.TryAddSingleton<CertificateProvider>();
        services.TryAddSingleton<PermissionProvider>();
        services.TryAddSingleton<FtpListingFormatter>();
        services.TryAddSingleton<AsciiSizeCache>();
        services.TryAddSingleton<FtpSessionProvider>();
        services.TryAddSingleton<FtpConnectionLimiter>();
        services.TryAddSingleton<IFtpAuthenticator, DefaultFtpAuthenticator>();
        services.TryAddSingleton<FtpCommandHandler, DefaultFtpCommandHandler>();
        services.TryAddSingleton<PassivePortProvider>();
        services.AddHostedService<PassivePortProviderHostedService>();
        services.AddHostedService<StartupValidationHostedService>();

        // Validation deliberately does not go through options validation: it has to run again on
        // every reload, where a failure must be reported and the previous configuration kept
        // rather than thrown from the file watcher's thread. FtpOptionsProvider owns both calls.
        services.AddOptions<FtpOptions>();

        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        return services;
    }
}
