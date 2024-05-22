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

        if (configure != null)
        {
            services.Configure(configure);
        }

        return services;
    }
}
