using Microsoft.AspNetCore.Connections;

namespace FtpServer.Handlers;

public class FtpKestrelConnectionHandler(
    FtpSessionProvider sessionProvider,
    FtpConnectionHandler connectionHandler
) : ConnectionHandler
{
    public override async Task OnConnectedAsync(ConnectionContext connection)
    {
        using var session = sessionProvider.CreateSession(connection.Transport);
        var token = connection.ConnectionClosed;

        session.RemoteEndPoint = connection.RemoteEndPoint;
        session.LocalEndPoint = connection.LocalEndPoint;

        await connectionHandler.HandleConnection(session, connection.Transport, token);
    }
}
