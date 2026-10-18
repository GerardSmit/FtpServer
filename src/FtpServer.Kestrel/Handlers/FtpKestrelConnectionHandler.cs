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

        // A peer that stops reading would otherwise keep a blocked reply, and the connection,
        // alive; Kestrel only closes the transport on request.
        session.AbortTransport = connection.Abort;

        await connectionHandler.HandleConnection(session, connection.Transport, connection.ConnectionClosed, ImplicitTls);
    }

    /// <summary>Whether this endpoint is implicit FTPS (TLS before the greeting).</summary>
    protected virtual bool ImplicitTls => false;
}
