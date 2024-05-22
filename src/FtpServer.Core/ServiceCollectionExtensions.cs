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
        services.TryAddSingleton<CertificateProvider>();
        services.TryAddSingleton<PermissionProvider>();
        services.TryAddSingleton<FtpSessionProvider>();
        services.TryAddSingleton<FtpCommandHandler, DefaultFtpCommandHandler>();
        services.TryAddSingleton<PassivePortProvider>();
        services.AddHostedService<PassivePortProviderHostedService>();

        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        return services;
    }
}
