using System.Net;
using FtpServer.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace FtpServer.Services;

public class FtpHostedService(
    FtpListener listener,
    IOptions<FtpOptions> options
) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        listener.Listen(endPoint: new IPEndPoint(IPAddress.IPv6Any, options.Value.Port));
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        listener.Stop();
        return Task.CompletedTask;
    }
}
