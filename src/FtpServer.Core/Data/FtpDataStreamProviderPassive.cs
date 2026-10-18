using System.Net;
using System.Net.Sockets;
using FtpServer.Options;
using Microsoft.Extensions.DependencyInjection;

namespace FtpServer.Data;

/// <summary>
/// Holds the port rented by PASV/EPSV until a transfer command claims it. The accept itself is
/// deferred to <see cref="CreateDataChannelAsync"/> so PASV can answer immediately and the client
/// is never sent two replies for one command.
/// </summary>
public sealed class FtpDataStreamProviderPassive(PassiveSocketOwner owner, EndPoint? controlPeer) : FtpDataStreamProvider
{
    private int _consumed;

    public override async ValueTask<FtpStream> CreateDataChannelAsync(FtpSession session, CancellationToken token)
    {
        if (Interlocked.Exchange(ref _consumed, 1) == 1)
        {
            throw new FtpDataConnectionException("425 Use PORT or PASV first.");
        }

        // A passive port serves exactly one transfer; the next one needs a fresh PASV.
        session.DataStreamProvider = Active;

        // Past the time the client had to connect after PASV, the port has gone back to the pool.
        if (!owner.TryClaim())
        {
            throw new FtpDataConnectionException("425 Can't open data connection: timed out waiting for the client.");
        }

        var options = session.RootServiceProvider.GetRequiredService<FtpOptionsProvider>().Current;
        Socket socket;

        try
        {
            socket = await owner.GetSocketAsync().WaitAsync(options.DataConnection.Timeout, token);
        }
        catch (TimeoutException)
        {
            owner.Dispose();
            throw new FtpDataConnectionException("425 Can't open data connection: timed out waiting for the client.");
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        Stream stream;

        try
        {
            VerifyPeer(socket, options);

            stream = new NetworkStream(socket, ownsSocket: false);

            if (session.DataConnectionMode != FtpDataConnectionMode.Clear)
            {
                stream = await DataConnectionTls.AuthenticateAsync(session, stream, options, token);
            }
        }
        catch
        {
            socket.Dispose();
            owner.Dispose();
            throw;
        }

        return new PassiveFtpStream(stream, socket, owner);
    }

    private void VerifyPeer(Socket socket, FtpOptions options)
    {
        if (!options.DataConnection.VerifyPeerAddress)
        {
            return;
        }

        // RFC 2577 section 3: refuse a data connection from anywhere but the control peer,
        // otherwise a third party can race the client and steal the transfer.
        if (Normalize(controlPeer) is not { } expected ||
            Normalize(socket.RemoteEndPoint) is not { } actual)
        {
            return;
        }

        if (!expected.Equals(actual))
        {
            throw new FtpDataConnectionException("425 Can't open data connection: address mismatch.");
        }
    }

    private static IPAddress? Normalize(EndPoint? endPoint)
    {
        if (endPoint is not IPEndPoint ip)
        {
            return null;
        }

        return ip.Address.IsIPv4MappedToIPv6 ? ip.Address.MapToIPv4() : ip.Address;
    }

    public override ValueTask ReleaseAsync()
    {
        if (Interlocked.Exchange(ref _consumed, 1) == 0)
        {
            owner.Dispose();
        }

        return ValueTask.CompletedTask;
    }
}

public sealed class PassiveFtpStream(Stream stream, Socket socket, PassiveSocketOwner owner) : FtpStream
{
    public override Stream Stream => stream;

    protected override async ValueTask DisposeAsyncCore()
    {
        try
        {
            await DataConnectionTls.CloseAsync(stream, socket);
        }
        finally
        {
            owner.Dispose();
        }
    }
}
