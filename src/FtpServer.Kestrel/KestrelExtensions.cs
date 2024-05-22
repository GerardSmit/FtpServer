using FtpServer.Handlers;
using FtpServer.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace FtpServer;

public static class KestrelExtensions
{
    public static KestrelServerOptions AddFtpServer(this KestrelServerOptions options, Action<ListenOptions>? configure = null)
    {
        var ftpOptions = options.ApplicationServices.GetRequiredService<IOptions<FtpOptions>>().Value;

        options.ListenAnyIP(ftpOptions.Port, listenOptions =>
        {
            configure?.Invoke(listenOptions);
            listenOptions.UseConnectionHandler<FtpKestrelConnectionHandler>();
        });

        return options;
    }

    public static IWebHostBuilder UseKestrelFtpServer(this IWebHostBuilder builder, Action<ListenOptions>? configure = null)
    {
        builder.ConfigureServices(services =>
        {
            services.AddFtpServerCore();
        });
        builder.UseKestrel((_, options) => options.AddFtpServer(configure));
        return builder;
    }
}
