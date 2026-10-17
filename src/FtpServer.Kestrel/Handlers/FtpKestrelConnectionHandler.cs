using Microsoft.AspNetCore.Connections;

namespace FtpServer.Handlers;

public class FtpKestrelConnectionHandler(
    FtpSessionProvider sessionProvider,
    FtpConnectionLimiter limiter,
    FtpConnectionHandler connectionHandler
) : ConnectionHandler
{
    public override async Task OnConnectedAsync(ConnectionContext connection)
    {
        using var lease = limiter.TryAcquire(connection.RemoteEndPoint);

        if (lease is null)
        {
            await connection.Transport.Output.WriteAsync("421 Too many connections, try again later.\r\n"u8.ToArray());
            return;
        }

        await using var session = sessionProvider.CreateSession(connection.Transport);

        session.RemoteEndPoint = connection.RemoteEndPoint;
        session.LocalEndPoint = connection.LocalEndPoint;

        await connectionHandler.HandleConnection(session, connection.Transport, connection.ConnectionClosed);
    }
}
