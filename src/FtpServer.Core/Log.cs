using System.Buffers;
using System.Net;
using Microsoft.Extensions.Logging;

namespace FtpServer;

public static partial class Log
{
    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Error,
        Message = "An error occurred while processing the request")]
    public static partial void RequestException(ILogger logger, Exception ex);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Debug,
        Message = "Handled request {Command} ({CommandName}) in {Elapsed:0.000} ms")]
    public static partial void IncomingRequest(ILogger logger, FtpCommand command, string commandName, double elapsed);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Debug,
        Message = "Passive connection ({EndPoint}) accepted in {Elapsed:0.000} ms")]
    public static partial void PassiveConnectionAccepted(ILogger logger, IPAddress? endPoint, double elapsed);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Warning,
        Message = "Error starting passive socket")]
    public static partial void CouldNotStartPassiveSocket(ILogger logger, Exception ex);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Warning,
        Message = "Error accepting passive socket")]
    public static partial void CouldNotAcceptPassiveSocket(ILogger logger, Exception ex);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Information,
        Message = "Accepting connection from {EndPoint}")]
    public static partial void AcceptConnection(ILogger logger, string? endPoint);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Information,
        Message = "FTP server started on {EndPoint}")]
    public static partial void ServerStarted(ILogger logger, string? endPoint);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Warning,
        Message = "Unhandled command {Command}")]
    public static partial void UnhandledCommand(ILogger logger, string command);
}