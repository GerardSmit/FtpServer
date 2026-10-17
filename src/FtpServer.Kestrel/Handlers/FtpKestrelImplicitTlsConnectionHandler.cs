namespace FtpServer.Handlers;

/// <summary>
/// Serves implicit FTPS: TLS from the first byte, before the greeting. Bound to
/// <see cref="Options.FtpOptions.ImplicitTlsPort"/> by <c>AddFtpServer</c>.
/// </summary>
/// <remarks>
/// The handshake is the FTP server's own rather than Kestrel's UseHttps, so it uses the same
/// certificate and TLS session cache as the data connections - which clients that require the
/// data channel to resume the control channel's session depend on.
/// </remarks>
public class FtpKestrelImplicitTlsConnectionHandler(
    FtpSessionProvider sessionProvider,
    FtpConnectionLimiter limiter,
    FtpConnectionHandler connectionHandler
) : FtpKestrelConnectionHandler(sessionProvider, limiter, connectionHandler)
{
    protected override bool ImplicitTls => true;
}
