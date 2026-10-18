using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using FtpServer.Options;
using Microsoft.Extensions.DependencyInjection;

namespace FtpServer.Data;

/// <summary>
/// Opens the data connection by dialling out to the endpoint named by PORT/EPRT.
/// Stateless, so a single shared instance serves every session.
/// </summary>
public sealed class FtpDataStreamProviderActive : FtpDataStreamProvider
{
    public override async ValueTask<FtpStream> CreateDataChannelAsync(FtpSession session, CancellationToken token)
    {
        // RFC 959 section 3.3: with no PORT and no passive command, the data connection goes to
        // the user-DTP's default port, which is the port the control connection came from. The
        // peer is the one already talking to us, so this cannot be aimed at a third party.
        var target = session.ActiveDataIp ?? session.RemoteEndPoint as IPEndPoint;

        if (target is null)
        {
            throw new FtpDataConnectionException("425 Use PORT or PASV first.");
        }

        var options = session.RootServiceProvider.GetRequiredService<FtpOptionsProvider>().Current;
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        Stream stream;

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(options.DataConnection.ConnectTimeout);

            try
            {
                await socket.ConnectAsync(target, timeout.Token);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                throw new FtpDataConnectionException("425 Can't open data connection.");
            }
            catch (SocketException)
            {
                throw new FtpDataConnectionException("425 Can't open data connection.");
            }

            stream = new NetworkStream(socket, ownsSocket: false);

            if (session.DataConnectionMode != FtpDataConnectionMode.Clear)
            {
                stream = await DataConnectionTls.AuthenticateAsync(session, stream, options, token);
            }
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return new ActiveFtpStream(stream, socket);
    }
}

public sealed class ActiveFtpStream(Stream stream, Socket socket) : FtpStream
{
    public override Stream Stream => stream;

    protected override ValueTask DisposeAsyncCore() => DataConnectionTls.CloseAsync(stream, socket);
}

/// <summary>
/// Raised when the data connection cannot be established. Carries the reply the client should get,
/// so the command handler can answer properly instead of leaving the session hanging.
/// </summary>
public sealed class FtpDataConnectionException(string reply) : Exception(reply)
{
    /// <summary>Full FTP reply line, without the trailing CRLF.</summary>
    public string Reply { get; } = reply;
}

internal static class DataConnectionTls
{
    public static async ValueTask<Stream> AuthenticateAsync(FtpSession session, Stream inner, FtpOptions options, CancellationToken token)
    {
        // RFC 4217 section 4: the server is always the TLS server on the data connection,
        // regardless of which side opened the TCP connection.
        var sslStream = new SslStream(inner, leaveInnerStreamOpen: false);

        try
        {
            var certificateProvider = session.RootServiceProvider.GetRequiredService<CertificateProvider>();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(options.Connection.TlsHandshakeTimeout);

            // The control connection's certificate, so a renewal mid-session cannot stop the data
            // connection resuming its TLS session.
            var tlsOptions = session.TlsCertificateContext is { } certificateContext
                ? certificateProvider.CreateServerAuthenticationOptions(certificateContext)
                : certificateProvider.CreateServerAuthenticationOptions();

            await sslStream.AuthenticateAsServerAsync(tlsOptions, timeout.Token);
        }
        catch (Exception ex)
        {
            await sslStream.DisposeAsync();

            throw ex is OperationCanceledException && !token.IsCancellationRequested
                ? new FtpDataConnectionException("425 Can't open data connection: TLS handshake timed out.")
                : ex;
        }

        return sslStream;
    }

    /// <summary>
    /// How long the TLS close_notify may take before the connection is simply dropped.
    /// </summary>
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(5);

    public static async ValueTask CloseAsync(Stream stream, Socket socket)
    {
        try
        {
            if (stream is SslStream sslStream)
            {
                // close_notify tells the peer the transfer ended cleanly rather than being
                // truncated - but it is a write, so a peer that has stopped reading would block
                // teardown forever and pin the session, which is precisely the stall the
                // transfer's own inactivity deadline just escaped from.
                using var timeout = new CancellationTokenSource(ShutdownTimeout);

                try
                {
                    await sslStream.ShutdownAsync().WaitAsync(timeout.Token);
                }
                catch (OperationCanceledException)
                {
                    // Abandon the graceful close; disposing the socket below tears it down.
                }
            }

            await stream.DisposeAsync();

            try
            {
                socket.Shutdown(SocketShutdown.Both);
            }
            catch
            {
                // Already closed by the peer.
            }
        }
        catch
        {
            // A failure while closing must not mask the transfer's own outcome.
        }
        finally
        {
            socket.Dispose();
        }
    }
}
