using System.Net;
using FtpServer.Handlers;
using Microsoft.Extensions.Logging;

namespace FtpServer.Services;

public class DefaultFtpListener(
    FtpSessionProvider provider,
    FtpConnectionLimiter limiter,
    FtpConnectionHandler handler,
    ILogger<DefaultFtpListener> logger) : FtpListener(provider, limiter)
{
    protected override async Task OnClientConnectedAsync(FtpSession session, CancellationToken token)
    {
        Log.AcceptConnection(logger, session.RemoteEndPoint?.ToString());

        // Passing the listener's token means shutdown actually reaches an in-flight transfer.
        await handler.HandleConnection(session, session.Transport, token);
    }

    protected override void OnStarted(EndPoint endPoint)
    {
        Log.ServerStarted(logger, endPoint.ToString());
    }

    protected override void OnConnectionRefused(EndPoint? remoteEndPoint)
    {
        Log.ConnectionRefused(logger, remoteEndPoint?.ToString(), "connection limit reached");
    }

    protected override void OnClientFaulted(FtpSession client, Exception exception)
    {
        // A peer vanishing is routine, not a server error; logging it as one would let any
        // client fill the log by resetting connections.
        if (IsConnectionDropped(exception))
        {
            Log.ConnectionDropped(logger, client.RemoteEndPoint?.ToString(), exception);
            return;
        }

        Log.RequestException(logger, exception);
    }

    protected override void OnServerFaulted(Exception exception)
    {
        Log.RequestException(logger, exception);
    }

    private static bool IsConnectionDropped(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is System.Net.Sockets.SocketException or ObjectDisposedException or IOException)
            {
                return true;
            }
        }

        return false;
    }
}
