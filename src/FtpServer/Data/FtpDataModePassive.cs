using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace FtpServer.Data;

public class FtpDataModePassive( Stream stream, Socket socket, SocketOwner owner) : FtpDataMode
{
    public override ValueTask<FtpStream> CreateDataChannelAsync(FtpSession session, CancellationToken token)
    {
        session.Mode = Active;

        // Passive mode is already established
        return new ValueTask<FtpStream>(new PassiveFtpStream(stream, socket, owner));
    }
}

public sealed class PassiveFtpStream(Stream stream, Socket socket, SocketOwner owner) : FtpStream
{
    public override Stream Stream => stream;

    protected override async ValueTask DisposeAsyncCore()
    {
        try
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
        finally
        {
            owner.Dispose();
        }
    }
}