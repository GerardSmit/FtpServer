using System.Net;
using FtpServer.Handlers;
using Microsoft.Extensions.Logging;

namespace FtpServer.Services;

public class DefaultFtpListener(
    FtpSessionProvider provider,
    FtpConnectionHandler handler,
    ILogger<DefaultFtpListener> logger) : FtpListener(provider)
{
    protected override async Task OnClientConnectedAsync(FtpSession session)
    {
        if (logger.IsEnabled(LogLevel.Trace))
        {
            logger.LogTrace("Accepting connection from {RemoteEndPoint}", session.RemoteEndPoint?.ToString());
        }

        await handler.HandleConnection(session, session.Transport, default);
    }

    protected override void OnStarted(EndPoint endPoint)
    {
        if (logger.IsEnabled(LogLevel.Information))
        {
            logger.LogInformation("FTP server started on {EndPoint}", endPoint.ToString());
        }
    }
}
