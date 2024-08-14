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
        Log.AcceptConnection(logger, session.RemoteEndPoint?.ToString());

        await handler.HandleConnection(session, session.Transport, default);
    }

    protected override void OnStarted(EndPoint endPoint)
    {
        Log.ServerStarted(logger, endPoint.ToString());
    }
}
