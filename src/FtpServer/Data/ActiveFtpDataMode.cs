using System.Net.Security;
using System.Net.Sockets;

namespace FtpServer.Data;

public sealed class ActiveFtpDataMode : FtpDataMode
{
    public override async ValueTask<FtpStream> CreateDataChannelAsync(FtpSession session, CancellationToken token)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

        if (session.ActiveDataIp is null)
        {
            throw new InvalidOperationException("Active data IP is not set.");
        }

        try
        {
            await socket.ConnectAsync(session.ActiveDataIp, token);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var stream = new NetworkStream(socket, ownsSocket: true);

        if (session.DataConnectionMode == FtpDataConnectionMode.Clear)
        {
            return new ActiveFtpStream(stream, socket);
        }

        var sslStream = new SslStream(stream, leaveInnerStreamOpen: false);

        try
        {
            await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = session.CertificateProvider.GetCertificate(),

            }, token);
        }
        catch
        {
            await sslStream.DisposeAsync();
            throw;
        }

        return new ActiveFtpStream(sslStream, socket);
    }
}

public sealed class ActiveFtpStream(Stream stream, Socket socket) : FtpStream
{
    public override Stream Stream => stream;

    protected override async ValueTask DisposeAsyncCore()
    {
        if (stream is SslStream sslStream)
        {
            await sslStream.ShutdownAsync();
        }

        try
        {
            socket.Shutdown(SocketShutdown.Both);
        }
        catch
        {
            // Ignore
        }

        await stream.DisposeAsync();
        socket.Dispose();
    }
}