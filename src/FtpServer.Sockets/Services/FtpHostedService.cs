using System.Net;
using FtpServer.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpServer.Services;

public class FtpHostedService(
    FtpListener listener,
    FtpSessionProvider sessionProvider,
    IServiceProvider services,
    IOptions<FtpOptions> options,
    ILogger<FtpHostedService> logger
) : IHostedService
{
    /// <summary>
    /// The service key of the listener that serves <see cref="FtpOptions.ImplicitTlsPort"/>. An
    /// application replacing <see cref="FtpListener"/> registers its type under this key as well.
    /// </summary>
    public const string ImplicitTlsListenerKey = "FtpServer.ImplicitTls";

    /// <summary>The implicit FTPS listener, when <see cref="FtpOptions.ImplicitTlsPort"/> is set.</summary>
    private FtpListener? _implicitListener;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Surfaces the effective root at startup, so a misconfigured Path is obvious immediately
        // rather than after a client connects.
        Log.ServingRoot(logger, sessionProvider.RootPath);

        listener.Listen(endPoint: new IPEndPoint(IPAddress.IPv6Any, options.Value.Port));

        if (options.Value.ImplicitTlsPort is { } implicitPort)
        {
            // A listener owns a single socket, so the implicit port has an instance of its own,
            // registered under a key (see SocketsExtensions.AddFtpServer).
            _implicitListener = services.GetRequiredKeyedService<FtpListener>(ImplicitTlsListenerKey);
            _implicitListener.Listen(endPoint: new IPEndPoint(IPAddress.IPv6Any, implicitPort), implicitTls: true);
        }

        return Task.CompletedTask;
    }

    // Awaited, so the host does not report the server stopped while sessions are still being
    // served on sockets it is about to tear down.
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_implicitListener is { } implicitListener)
        {
            // The container owns and disposes the keyed singleton; stopping is enough here.
            await Task.WhenAll(listener.StopAsync(), implicitListener.StopAsync());
            _implicitListener = null;
            return;
        }

        await listener.StopAsync();
    }
}
