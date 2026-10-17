using System.Net;
using Microsoft.Extensions.Logging;

namespace FtpServer;

public static partial class Log
{
    // 1xx - connection lifecycle
    [LoggerMessage(EventId = 100, Level = LogLevel.Information, Message = "FTP server started on {EndPoint}")]
    public static partial void ServerStarted(ILogger logger, string? endPoint);

    [LoggerMessage(EventId = 101, Level = LogLevel.Information, Message = "Accepting connection from {EndPoint}")]
    public static partial void AcceptConnection(ILogger logger, string? endPoint);

    [LoggerMessage(EventId = 102, Level = LogLevel.Warning, Message = "Refused connection from {EndPoint}: {Reason}")]
    public static partial void ConnectionRefused(ILogger logger, string? endPoint, string reason);

    [LoggerMessage(EventId = 103, Level = LogLevel.Debug, Message = "Handled request {Command} ({CommandName}) in {Elapsed:0.000} ms")]
    public static partial void IncomingRequest(ILogger logger, FtpCommand command, string commandName, double elapsed);

    [LoggerMessage(EventId = 104, Level = LogLevel.Debug, Message = "Unhandled command {Command}")]
    public static partial void UnhandledCommand(ILogger logger, string command);

    // 2xx - errors
    [LoggerMessage(EventId = 200, Level = LogLevel.Error, Message = "An error occurred while processing the request")]
    public static partial void RequestException(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 201, Level = LogLevel.Debug, Message = "Could not send reply to the client")]
    public static partial void ReplyFailed(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 204, Level = LogLevel.Warning, Message = "Refused a request that resolved outside the served tree or was denied by the host")]
    public static partial void RequestRefused(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 203, Level = LogLevel.Debug, Message = "Connection from {EndPoint} dropped")]
    public static partial void ConnectionDropped(ILogger logger, string? endPoint, Exception ex);

    [LoggerMessage(EventId = 202, Level = LogLevel.Warning, Message = "Client pipelined data before the TLS handshake; closing the connection")]
    public static partial void PipelinedDataBeforeTlsUpgrade(ILogger logger);

    // Debug: a port scanner or a plain-FTP client on the implicit port fails the handshake
    // routinely, and logging that louder would let any peer fill the log.
    [LoggerMessage(EventId = 205, Level = LogLevel.Debug, Message = "Implicit TLS handshake with {EndPoint} failed; closing the connection")]
    public static partial void ImplicitTlsHandshakeFailed(ILogger logger, string? endPoint, Exception ex);

    // 3xx - data connections
    [LoggerMessage(EventId = 300, Level = LogLevel.Debug, Message = "Passive connection ({EndPoint}) accepted in {Elapsed:0.000} ms")]
    public static partial void PassiveConnectionAccepted(ILogger logger, IPAddress? endPoint, double elapsed);

    [LoggerMessage(EventId = 301, Level = LogLevel.Warning, Message = "Error starting passive socket")]
    public static partial void CouldNotStartPassiveSocket(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 302, Level = LogLevel.Warning, Message = "Error accepting passive socket")]
    public static partial void CouldNotAcceptPassiveSocket(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 303, Level = LogLevel.Warning, Message = "Closing unclaimed passive connection from {EndPoint}")]
    public static partial void UnmatchedPassiveConnection(ILogger logger, IPAddress? endPoint);

    [LoggerMessage(EventId = 304, Level = LogLevel.Warning, Message = "Listing of {Path} truncated at {Limit} entries")]
    public static partial void ListingTruncated(ILogger logger, string path, int limit);

    // 4xx - authentication
    [LoggerMessage(EventId = 400, Level = LogLevel.Information, Message = "User {UserName} logged in from {EndPoint}")]
    public static partial void LoginSucceeded(ILogger logger, string userName, string endPoint);

    [LoggerMessage(EventId = 401, Level = LogLevel.Warning, Message = "Failed login for {UserName} from {EndPoint}")]
    public static partial void LoginFailed(ILogger logger, string userName, string endPoint);

    [LoggerMessage(EventId = 402, Level = LogLevel.Warning, Message = "Refusing login for {UserName} from {EndPoint}: too many failed attempts")]
    public static partial void LoginLockedOut(ILogger logger, string userName, string endPoint);

    [LoggerMessage(EventId = 403, Level = LogLevel.Warning, Message = "Refusing HOST {Host}: the TLS handshake named {ServerName}")]
    public static partial void HostContradictsSni(ILogger logger, string host, string serverName);

    // 5xx - configuration
    [LoggerMessage(EventId = 500, Level = LogLevel.Information, Message = "Loading TLS certificate from {Path}")]
    public static partial void LoadingCertificate(ILogger logger, string path);

    [LoggerMessage(EventId = 501, Level = LogLevel.Warning, Message = "No certificate configured; generating a self-signed certificate for {Subject}. Clients will not be able to verify it.")]
    public static partial void GeneratingSelfSignedCertificate(ILogger logger, string subject);

    [LoggerMessage(EventId = 502, Level = LogLevel.Information, Message = "Serving {Path} as the FTP root")]
    public static partial void ServingRoot(ILogger logger, string path);

    [LoggerMessage(EventId = 503, Level = LogLevel.Warning, Message = "User {UserName} is configured with a plain password or a bare SHA-256 digest, which can be cracked offline if the configuration leaks. Use PasswordHash instead.")]
    public static partial void WeakPasswordStorage(ILogger logger, string userName);

    [LoggerMessage(EventId = 504, Level = LogLevel.Information, Message = "Configuration reloaded")]
    public static partial void ConfigurationReloaded(ILogger logger);

    [LoggerMessage(EventId = 505, Level = LogLevel.Error, Message = "Reloaded configuration is invalid and was ignored; the server keeps running with the previous one")]
    public static partial void ConfigurationReloadRejected(ILogger logger, Exception ex);

    [LoggerMessage(EventId = 506, Level = LogLevel.Warning, Message = "Virtual folder {Path} of user {UserName} could not be mounted")]
    public static partial void VirtualFolderMountFailed(ILogger logger, string path, string userName, Exception ex);

    [LoggerMessage(EventId = 507, Level = LogLevel.Error, Message = "Settings file {Path} could not be read and was ignored; the server keeps running with the previous configuration")]
    public static partial void SettingsFileUnreadable(ILogger logger, string path, Exception ex);
}
