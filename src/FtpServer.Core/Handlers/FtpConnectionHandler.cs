using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net.Security;
using System.Security.Authentication;
using FtpServer.Data;
using FtpServer.Extensions;
using FtpServer.Options;
using FtpServer.Pipelines;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer.Handlers;

public partial class FtpConnectionHandler(
    IHostApplicationLifetime lifetime,
    CertificateProvider provider,
    FtpCommandHandler handler,
    FtpSessionProvider sessionProvider,
    FtpOptionsProvider options,
    ILogger<FtpConnectionHandler> logger)
{
    private static readonly StreamPipeReaderOptions SslReaderOptions = new(leaveOpen: true);
    private static readonly StreamPipeWriterOptions SslWriterOptions = new(leaveOpen: true);

    /// <summary>Commands that run a data transfer and are therefore allowed to overlap with ABOR.</summary>
    private static bool IsTransferCommand(FtpCommand command) => command is
        FtpCommand.ListInformation or
        FtpCommand.ListFileNames or
        FtpCommand.ListDirectoryContents or
        FtpCommand.RetrieveFile or
        FtpCommand.StoreFile or
        FtpCommand.StoreFileUniquely or
        FtpCommand.Append;

    /// <param name="implicitTls">
    /// True for the implicit FTPS port: the TLS handshake comes first, before the greeting, and
    /// the session is protected from its very first reply.
    /// </param>
    public async Task HandleConnection(FtpSession session, IDuplexPipe pipe, CancellationToken token, bool implicitTls = false)
    {
        var connection = options.Current.Connection;
        var input = pipe.Input;

        // Kept so REIN can hand the connection back to the clear (RFC 4217 section 13).
        var clearPipe = pipe;

        var didSwitchProtocol = false;
        Task? activeTransfer = null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(lifetime.ApplicationStopping, token);

        if (implicitTls)
        {
            try
            {
                pipe = await AuthenticateAsServerAsync(session, pipe, cts.Token);
            }
            catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException)
            {
                // Nothing has been said yet, so there is nobody to tell; the transport closes.
                Log.ImplicitTlsHandshakeFailed(logger, session.RemoteEndPoint?.ToString(), ex);
                return;
            }

            didSwitchProtocol = true;
            input = pipe.Input;

            session.Transport = pipe;
            session.IsProtected = true;
            session.IsImplicitTls = true;
            session.ResetProtectionParameters();
        }

        await session.WriteAsync("220 Service ready for new user.\r\n"u8, cts.Token);

        try
        {
            while (!cts.Token.IsCancellationRequested)
            {
                ReadResult result;

                // A transfer in flight means the session is not idle, even though a client sends
                // nothing on the control channel while data is moving. Arming the idle timer here
                // would kill any transfer that outlasts it, leaving the client a truncated file.
                var idleTimeout = activeTransfer is { IsCompleted: false }
                    ? Timeout.InfiniteTimeSpan
                    : connection.IdleTimeout;

                try
                {
                    result = await ReadAsync(input, idleTimeout, cts.Token);
                }
                catch (IdleTimeoutException)
                {
                    await TryWriteAsync(session, "421 Idle timeout, closing control connection.\r\n"u8);
                    break;
                }
                catch (OperationCanceledException) when (lifetime.ApplicationStopping.IsCancellationRequested)
                {
                    // RFC 959 section 4.2: tell the client the service is going away rather than
                    // dropping the connection silently.
                    await TryWriteAsync(session, "421 Service not available, closing control connection.\r\n"u8);
                    break;
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                // result.IsCanceled only comes from the CancelPendingRead a finished transfer
                // issues to re-arm the idle timer, so it is no reason to stop reading.

                var buffer = result.Buffer;
                var consumed = buffer.Start;
                var upgrade = false;
                var close = false;

                try
                {
                    while (TryReadLine(ref buffer, out var line))
                    {
                        consumed = buffer.Start;

                        if (line.Length > connection.MaxCommandLength)
                        {
                            await TryWriteAsync(session, "500 Syntax error, command line too long.\r\n"u8);
                            close = true;
                            break;
                        }

                        var length = (int)line.Length;
                        var rented = ArrayPool<byte>.Shared.Rent(Math.Max(length, 1));
                        var owned = true;

                        try
                        {
                            line.CopyTo(rented);
                            length = FtpRequest.StripTelnet(rented.AsSpan(0, length), out var negotiation);

                            if (negotiation is not null)
                            {
                                // Before the command it arrived with, in case the client is
                                // waiting for the refusal.
                                await TryWriteCoreAsync(session, negotiation);
                            }

                            // An empty line is a syntax error, not an unknown command.
                            if (length == 0)
                            {
                                await TryWriteAsync(session, "500 Syntax error, command unrecognized.\r\n"u8);
                                continue;
                            }

                            var (command, data) = FtpRequest.Parse(rented.AsMemory(0, length));

                            // A transfer is in flight: only ABOR and STAT may overtake it.
                            if (activeTransfer is { IsCompleted: false })
                            {
                                if (command == FtpCommand.Abort)
                                {
                                    await AbortTransferAsync(session, activeTransfer);
                                    activeTransfer = null;
                                    continue;
                                }

                                if (command != FtpCommand.ServerStatus)
                                {
                                    await activeTransfer;
                                    activeTransfer = null;
                                }
                            }
                            else if (activeTransfer is not null)
                            {
                                await activeTransfer;
                                activeTransfer = null;
                            }

                            if (command == FtpCommand.AuthenticationSecurityMechanism && options.Current.Ftps && !didSwitchProtocol)
                            {
                                if (!IsTlsMechanism(data.Span))
                                {
                                    await TryWriteAsync(session, "504 Command not implemented for that parameter.\r\n"u8);
                                    continue;
                                }

                                upgrade = true;
                                break;
                            }

                            var sw = Stopwatch.StartNew();

                            if (IsTransferCommand(command))
                            {
                                // Run in the background so the control connection stays readable
                                // and ABOR can still be received (RFC 959 section 4.1.3).
                                owned = false;
                                activeTransfer = RunCommandAsync(session, command, rented, length - data.Length, (int)data.Length, cts.Token);

                                // Wakes the read loop when the transfer ends, otherwise it blocks
                                // with the idle timer disarmed and never times out again.
                                var reader = input;

                                _ = activeTransfer.ContinueWith(
                                    static (_, state) =>
                                    {
                                        try
                                        {
                                            ((PipeReader)state!).CancelPendingRead();
                                        }
                                        catch
                                        {
                                            // The reader is already finished with.
                                        }
                                    },
                                    reader,
                                    CancellationToken.None,
                                    TaskContinuationOptions.ExecuteSynchronously,
                                    TaskScheduler.Default);
                            }
                            else
                            {
                                await RunCommandInlineAsync(session, command, new ReadOnlySequence<byte>(data), cts.Token);
                            }

                            if (logger.IsEnabled(LogLevel.Debug))
                            {
                                Log.IncomingRequest(logger, command, command.ToCommand(), sw.Elapsed.TotalMilliseconds);
                            }

                            // QUIT, or a handler that answered 421 and therefore promised to close.
                            if (command == FtpCommand.Disconnect || session.CloseRequested)
                            {
                                close = true;
                                break;
                            }

                            // REIN answered inside TLS and now wants the connection in the clear.
                            if (session.ClearProtectionRequested)
                            {
                                break;
                            }
                        }
                        finally
                        {
                            if (owned)
                            {
                                ArrayPool<byte>.Shared.Return(rented);
                            }
                        }
                    }

                    if (!upgrade && !close && !session.ClearProtectionRequested && buffer.Length > connection.MaxCommandLength)
                    {
                        // No terminator in sight and already over the limit: the peer is not
                        // speaking FTP, and leaving it buffered would grow without bound.
                        await TryWriteAsync(session, "500 Syntax error, command line too long.\r\n"u8);
                        close = true;
                    }
                }
                finally
                {
                    // `consumed` always points past the last line we finished with, so a command
                    // that throws can never be replayed on the next read.
                    input.AdvanceTo(consumed, upgrade || close || session.ClearProtectionRequested ? consumed : buffer.End);
                }

                if (close)
                {
                    break;
                }

                if (upgrade)
                {
                    if (!buffer.IsEmpty)
                    {
                        // Anything pipelined behind AUTH arrived in the clear and would be
                        // replayed inside the TLS session. Refuse rather than execute it.
                        Log.PipelinedDataBeforeTlsUpgrade(logger);
                        await TryWriteAsync(session, "421 Unexpected data before TLS handshake.\r\n"u8);
                        break;
                    }

                    // Only set once the handshake has succeeded; earlier, a failed handshake left
                    // the cleanup block tearing down the raw pipe and leaking the half-built one.
                    pipe = await SwitchProtocolAsync(session, pipe, cts.Token);
                    didSwitchProtocol = true;

                    session.Transport = pipe;
                    session.IsProtected = true;
                    input = pipe.Input;

                    await ResetAfterAuthAsync(session);
                    continue;
                }

                if (session.ClearProtectionRequested)
                {
                    session.ClearProtectionRequested = false;

                    if (!buffer.IsEmpty)
                    {
                        // Sent protected, and would be answered in the clear.
                        Log.PipelinedDataBeforeTlsUpgrade(logger);
                        await TryWriteAsync(session, "421 Unexpected data before clearing the security layer.\r\n"u8);
                        break;
                    }

                    await ShutdownTlsAsync(pipe);

                    pipe = clearPipe;
                    didSwitchProtocol = false;

                    session.Transport = pipe;
                    session.IsProtected = false;
                    session.TlsCertificateContext = null;
                    input = pipe.Input;
                    continue;
                }

                if (result.IsCompleted)
                {
                    // Writer completed and nothing more can be framed; without this the loop
                    // would spin on the same completed result forever.
                    break;
                }
            }
        }
        finally
        {
            if (activeTransfer is not null)
            {
                // Cancelling and awaiting are separate: the CTS may already have been disposed by
                // the transfer's own finally, and swallowing the await would leave it running.
                try
                {
                    session.TransferCancellation?.Cancel();
                }
                catch (ObjectDisposedException)
                {
                    // The transfer finished first.
                }

                try
                {
                    await activeTransfer;
                }
                catch
                {
                    // The session is going away; the transfer's outcome no longer matters.
                }
            }

            // A closing reply (421/221) has only reached the socket layer at this point, and
            // disposing the connection now can discard it.
            await LingerAsync(input);

            if (didSwitchProtocol)
            {
                await ShutdownTlsAsync(pipe);
            }
        }
    }

    /// <summary>
    /// Puts the session back to its pre-login state after the security layer has changed.
    /// </summary>
    /// <remarks>
    /// RFC 4217 section 4 requires the client to reauthorize after AUTH and every other transfer
    /// parameter to be reset "almost as if a REIN command was issued", so that nothing granted in
    /// the clear carries into the protected session. The RFC 7151 host stays, selecting the server
    /// rather than the user.
    /// </remarks>
    private async ValueTask ResetAfterAuthAsync(FtpSession session)
    {
        // A host the handshake contradicts cannot be honoured. RFC 7151 section 3.3 allows the
        // connection to carry on as though no HOST had been sent, so the client can try again.
        if (session is { VirtualHost: { } host, TlsServerName: { } serverName } &&
            !string.Equals(host, serverName, StringComparison.OrdinalIgnoreCase))
        {
            Log.HostContradictsSni(logger, host, serverName);
            session.VirtualHost = null;
        }

        // Released before the reset returns the provider to Active, or a port rented by an earlier
        // PASV stays registered with nobody able to claim or free it.
        await session.DataStreamProvider.ReleaseAsync();

        session.ResetForNewUser();
        session.ResetProtectionParameters();

        // Drops a per-user home mounted by the login that is being discarded.
        session.ReplaceFileSystem(sessionProvider.CreateFileSystem());
        session.IsReadOnly = options.Current.ReadOnly;
    }

    /// <summary>
    /// Waits, briefly, for the client to close after a final reply.
    /// </summary>
    /// <remarks>
    /// The peer closes once it has read the reply, so its FIN is the signal that the reply
    /// actually arrived. Bounded, because a client that neither reads nor closes must not be able
    /// to hold the connection here.
    /// </remarks>
    private static async Task LingerAsync(PipeReader input)
    {
        try
        {
            // Deliberately not linked to the session's token: on host shutdown that token is
            // already cancelled, which would skip the wait for the very reply announcing it.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));

            while (true)
            {
                var result = await input.ReadAsync(timeout.Token);

                // Anything still arriving is a command we will never answer; discard it.
                input.AdvanceTo(result.Buffer.End);

                // Only the peer closing ends the wait; IsCanceled is a stale CancelPendingRead
                // latch left by a finished transfer.
                if (result.IsCompleted)
                {
                    return;
                }
            }
        }
        catch
        {
            // Timed out, already completed, or the peer reset - nothing more to wait for.
        }
    }

    private async Task AbortTransferAsync(FtpSession session, Task transfer)
    {
        try
        {
            session.TransferCancellation?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // The transfer completed between the dispatch and this call.
        }

        try
        {
            await transfer;
        }
        catch
        {
            // The transfer reports its own outcome; ABOR only confirms the abort.
        }

        await TryWriteAsync(session, "226 ABOR command successful.\r\n"u8);
    }

    /// <summary>
    /// Runs a transfer command that owns <paramref name="rented"/> for its whole lifetime.
    /// </summary>
    private async Task RunCommandAsync(FtpSession session, FtpCommand command, byte[] rented, int offset, int length, CancellationToken token)
    {
        try
        {
            await RunCommandInlineAsync(session, command, new ReadOnlySequence<byte>(rented, offset, length), token);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>
    /// Dispatches a command and guarantees the client receives a reply, whatever happens.
    /// </summary>
    private async Task RunCommandInlineAsync(FtpSession session, FtpCommand command, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // RFC 959 sections 4.1.3 and 5.4: RNTO must follow RNFR immediately, so anything in
        // between - including a failed RNFR - abandons the rename.
        if (command != FtpCommand.RenameTo)
        {
            session.RenameFrom = null;
        }

        try
        {
            await handler.HandleAsync(session, command, data, token);
        }
        catch (FtpDataConnectionException ex)
        {
            await TryWriteAsync(session, ex.Reply + "\r\n");
        }
        catch (FtpArgumentException ex)
        {
            await TryWriteAsync(session, ex.Reply + "\r\n");
        }
        catch (OperationCanceledException) when (IsTransferCommand(command) && session.TransferCancellation is { IsCancellationRequested: true })
        {
            // Scoped to transfer commands: STAT may run alongside a transfer, and without this a
            // cancelled STAT would be answered with the transfer's 426.
            await TryWriteAsync(session, "426 Connection closed; transfer aborted.\r\n"u8);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException ex)
        {
            // Refused by the host or by root containment: the pathname is the problem, not the
            // server, so it is a 550 rather than a 451.
            Log.RequestRefused(logger, ex);
            await TryWriteAsync(session, "550 Requested action not taken: access denied.\r\n"u8);
        }
        catch (Exception ex)
        {
            Log.RequestException(logger, ex);
            await TryWriteAsync(session, "451 Requested action aborted. Local error in processing.\r\n"u8);
        }
    }

    /// <summary>
    /// Sends a reply, swallowing the failure that follows a peer disappearing mid-command.
    /// </summary>
    private ValueTask TryWriteAsync(FtpSession session, ReadOnlySpan<byte> reply) =>
        TryWriteCoreAsync(session, reply.ToArray());

    private ValueTask TryWriteAsync(FtpSession session, string reply) =>
        TryWriteCoreAsync(session, System.Text.Encoding.ASCII.GetBytes(reply));

    private async ValueTask TryWriteCoreAsync(FtpSession session, ReadOnlyMemory<byte> reply)
    {
        try
        {
            await session.WriteAsync(reply.Span);
        }
        catch (Exception ex)
        {
            // The peer is gone; nothing left to say.
            Log.ReplyFailed(logger, ex);
        }
    }

    private static bool IsTlsMechanism(ReadOnlySpan<byte> argument)
    {
        Span<byte> upper = stackalloc byte[8];

        if (argument.Length > upper.Length)
        {
            return false;
        }

        for (var i = 0; i < argument.Length; i++)
        {
            var b = argument[i];
            upper[i] = (byte)(b is >= (byte)'a' and <= (byte)'z' ? b - 32 : b);
        }

        var mechanism = upper[..argument.Length];

        // RFC 4217 registers TLS; TLS-C and SSL are the widely-deployed aliases.
        return mechanism.SequenceEqual("TLS"u8) ||
               mechanism.SequenceEqual("TLS-C"u8) ||
               mechanism.SequenceEqual("SSL"u8);
    }

    private static async Task<ReadResult> ReadAsync(PipeReader input, TimeSpan idleTimeout, CancellationToken token)
    {
        // Covers both a disabled timeout and Timeout.InfiniteTimeSpan, which the caller passes
        // while a transfer is running.
        if (idleTimeout <= TimeSpan.Zero)
        {
            return await input.ReadAsync(token);
        }

        using var timeoutCts = new CancellationTokenSource(idleTimeout);
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(token, timeoutCts.Token);

        try
        {
            return await input.ReadAsync(combined.Token);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !token.IsCancellationRequested)
        {
            throw new IdleTimeoutException();
        }
    }

    private async Task<IDuplexPipe> SwitchProtocolAsync(FtpSession session, IDuplexPipe pipe, CancellationToken token)
    {
        await session.WriteAsync("234 Proceed with authentication mechanism.\r\n"u8, token);
        return await AuthenticateAsServerAsync(session, pipe, token);
    }

    /// <summary>
    /// Runs the server side of the TLS handshake over <paramref name="pipe"/> and returns the
    /// protected pipe: after AUTH TLS, or straight away on the implicit FTPS port.
    /// </summary>
    private async Task<IDuplexPipe> AuthenticateAsServerAsync(FtpSession session, IDuplexPipe pipe, CancellationToken token)
    {
        var sslDuplex = new SslDuplexPipe(pipe, SslReaderOptions, SslWriterOptions);

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(options.Current.Connection.TlsHandshakeTimeout);

            // Selected from the client hello, the only place the SNI server name is visible.
            await sslDuplex.Stream.AuthenticateAsServerAsync(
                (_, clientHello, _, _) =>
                {
                    session.TlsServerName = string.IsNullOrEmpty(clientHello.ServerName) ? null : clientHello.ServerName;

                    // Remembered for the data connections, which present the same certificate
                    // even if it is replaced while this session is open.
                    var tlsOptions = provider.CreateServerAuthenticationOptions();
                    session.TlsCertificateContext = tlsOptions.ServerCertificateContext;
                    return ValueTask.FromResult(tlsOptions);
                },
                state: null,
                timeout.Token);
        }
        catch
        {
            // The caller has not adopted it yet, so nothing else would ever dispose it.
            await sslDuplex.Stream.DisposeAsync();
            throw;
        }

        return sslDuplex;
    }

    private static async Task ShutdownTlsAsync(IDuplexPipe pipe)
    {
        try
        {
            if (pipe is SslDuplexPipe { Stream: { } sslStream })
            {
                // Bounded: close_notify is a write, so a peer that has stopped reading would
                // otherwise stall teardown indefinitely.
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));

                try
                {
                    await sslStream.ShutdownAsync().WaitAsync(timeout.Token);
                }
                catch (OperationCanceledException)
                {
                    // Drop the graceful close; the pipe is disposed below regardless.
                }

                // Completing the pipe's reader and writer leaves the SslStream itself alive. It is
                // constructed with leaveInnerStreamOpen, so this does not touch the transport.
                await sslStream.DisposeAsync();
            }

            switch (pipe)
            {
                case IAsyncDisposable asyncDisposable:
                    await asyncDisposable.DisposeAsync();
                    break;
                case IDisposable disposable:
                    disposable.Dispose();
                    break;
            }
        }
        catch
        {
            // Best effort: the connection is closing either way.
        }
    }

    /// <summary>
    /// Frames one command line, accepting CRLF and the bare LF that some clients send.
    /// The terminator is not included in <paramref name="line"/>.
    /// </summary>
    internal static bool TryReadLine(ref ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> line)
    {
        var reader = new SequenceReader<byte>(buffer);

        if (!reader.TryReadTo(out line, (byte)'\n', advancePastDelimiter: true))
        {
            line = default;
            return false;
        }

        // Drop the CR of a CRLF pair; a bare LF leaves the line as-is. A one-byte slice always
        // lives in a single segment, so FirstSpan is enough.
        if (line.Length > 0 && line.Slice(line.Length - 1).FirstSpan[0] == (byte)'\r')
        {
            line = line.Slice(0, line.Length - 1);
        }

        buffer = buffer.Slice(reader.Position);
        return true;
    }

    private sealed class IdleTimeoutException : Exception;
}
