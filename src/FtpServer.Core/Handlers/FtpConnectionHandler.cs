using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net.Security;
using System.Runtime.CompilerServices;
using FtpServer.Options;
using FtpServer.Pipelines;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpServer.Handlers;

public partial class FtpConnectionHandler(
    IHostApplicationLifetime lifetime,
    CertificateProvider provider,
    FtpCommandHandler handler,
    IOptions<FtpOptions> options,
    ILogger<FtpConnectionHandler> logger)
{
    private static readonly StreamPipeReaderOptions SslReaderOptions = new(leaveOpen: true);
    private static readonly StreamPipeWriterOptions SslWriterOptions = new(leaveOpen: true);

    public async Task HandleConnection(FtpSession session, IDuplexPipe pipe, CancellationToken token)
    {
        var input = pipe.Input;
        var output = pipe.Output;

        var didSwitchProtocol = false;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(
            lifetime.ApplicationStopping,
            token
        );

        output.Write("220 Service ready for new user.\r\n"u8);
        await output.FlushAsync(cts.Token);

        while (!cts.Token.IsCancellationRequested)
        {
            Read:
            var hasBuffer = false;
            ReadOnlySequence<byte> buffer = default;

            try
            {
                var result = await ReadAsync(input, cts.Token);
                buffer = result.Buffer;
                hasBuffer = true;

                if (buffer.Length == 0)
                {
                    break;
                }

                while (TryGetLine("\r\n"u8, buffer, out var position))
                {
                    var line = result.Buffer.Slice(0, position);
                    var (command, data) = FtpRequest.Parse(line);
                    var sw = Stopwatch.StartNew();

                    if (command == FtpCommand.AuthenticationSecurityMechanism)
                    {
                        if (didSwitchProtocol)
                        {
                            // Already switched to the SSL protocol
                            output.Write("503 Bad sequence of commands.\r\n"u8);
                            await output.FlushAsync(cts.Token);
                            input.AdvanceTo(buffer.End);
                        }

                        if (options.Value.Ftps)
                        {
                            didSwitchProtocol = true;

                            // Advance to the end of the line
                            input.AdvanceTo(buffer.End);
                            hasBuffer = false;

                            // Switch to the SSL protocol
                            pipe = await SwitchProtocolAsync(pipe, cts.Token);
                            session.Transport = pipe;
                            input = pipe.Input;
                            output = pipe.Output;

                            goto Read;
                        }
                    }

                    await handler.HandleAsync(session, command, data, cts.Token);
                    buffer = buffer.Slice(position);

                    if (logger.IsEnabled(LogLevel.Debug))
                    {
                        Log.IncomingRequest(logger, command, command.ToCommand(), sw.Elapsed.TotalMilliseconds);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch(Exception ex)
            {
                Log.RequestException(logger, ex);
            }
            finally
            {
                if (hasBuffer)
                {
                    input.AdvanceTo(buffer.Start, buffer.End);
                }
            }
        }

        // When we switch the protocol, we need to dispose the pipe
        if (didSwitchProtocol)
        {
            if (pipe is SslDuplexPipe { Stream: { } sslStream })
            {
                await sslStream.ShutdownAsync();
            }

            if (pipe is IAsyncDisposable asyncDisposable)
            {
                await asyncDisposable.DisposeAsync();
            }
            else if (pipe is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    private static async Task<ReadResult> ReadAsync(PipeReader input, CancellationToken token)
    {
        using var timeOutCts = new CancellationTokenSource(30_000);
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(token, timeOutCts.Token);

        var result = await input.ReadAsync(combined.Token);

        combined.Token.ThrowIfCancellationRequested();

        return result;
    }

    private async Task<IDuplexPipe> SwitchProtocolAsync(IDuplexPipe pipe, CancellationToken token)
    {
        var output = pipe.Output;

        // Send the response
        output.Write("234 Proceed with authentication mechanism.\r\n"u8);
        await output.FlushAsync(token);

        // Start the SSL handshake
        var sslDuplex = new SslDuplexPipe(pipe, SslReaderOptions, SslWriterOptions);
        var sslStream = sslDuplex.Stream;

        await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = provider.GetCertificate(),
        }, token);

        return sslDuplex;
    }

    private static bool TryGetLine(in ReadOnlySpan<byte> span, in ReadOnlySequence<byte> result, out SequencePosition position)
    {
        if (!result.IsSingleSegment)
        {
            return TryGetLineMultiSegment(span, result, out position);
        }

        var index = result.First.Span.IndexOf(span);

        if (index != -1)
        {
            position = result.GetPosition(index + span.Length, result.Start);
            return true;
        }

        position = default;
        return false;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool TryGetLineMultiSegment(in ReadOnlySpan<byte> span, in ReadOnlySequence<byte> result, out SequencePosition position)
    {
        var reader = new SequenceReader<byte>(result);

        if (reader.TryReadTo(out ReadOnlySequence<byte> _, span))
        {
            position = reader.Position;
            return true;
        }

        position = default;
        return false;
    }
}
