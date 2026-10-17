using System.Net;
using FtpServer.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpServer.Services;

public class FtpHostedService(
    FtpListener listener,
    FtpSessionProvider sessionProvider,
    IOptions<FtpOptions> options,
    ILogger<FtpHostedService> logger
) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Surfaces the effective root at startup, so a misconfigured Path is obvious immediately
        // rather than after a client connects.
        Log.ServingRoot(logger, sessionProvider.RootPath);

        listener.Listen(endPoint: new IPEndPoint(IPAddress.IPv6Any, options.Value.Port));
        return Task.CompletedTask;
    }

    // Awaited, so the host does not report the server stopped while sessions are still being
    // served on sockets it is about to tear down.
    public Task StopAsync(CancellationToken cancellationToken) => listener.StopAsync();
}
