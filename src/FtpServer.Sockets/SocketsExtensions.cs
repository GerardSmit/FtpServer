using FtpServer.Options;
using FtpServer.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace FtpServer;

public static class SocketsExtensions
{
    public static IServiceCollection AddFtpServer(this IServiceCollection services, Action<FtpOptions>? configure = null)
    {
        services.AddFtpServerCore();
        services.AddHostedService<FtpHostedService>();
        services.TryAddSingleton<FtpListener, DefaultFtpListener>();

        // A separate instance for the implicit FTPS port, used only when ImplicitTlsPort is set.
        services.TryAddKeyedSingleton<FtpListener, DefaultFtpListener>(FtpHostedService.ImplicitTlsListenerKey);

        if (configure != null)
        {
            services.Configure(configure);
        }

        return services;
    }
}
