using System.Buffers;
using System.IO.Pipelines;
using System.Net.Security;
using System.Runtime.CompilerServices;
using FtpServer.Kestrel.Pipelines;
using FtpServer.Options;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

namespace FtpServer.Handlers;

public class FtpConnectionHandler(
    IHostApplicationLifetime lifetime,
    CertificateProvider provider,
    FtpCommandHandler handler,
    FtpSessionProvider sessionProvider,
    IOptions<FtpOptions> options
) : ConnectionHandler
{
    private static readonly StreamPipeReaderOptions SslReaderOptions = new(leaveOpen: true);
    private static readonly StreamPipeWriterOptions SslWriterOptions = new(leaveOpen: true);

    public override async Task OnConnectedAsync(ConnectionContext connection)
    {
        using var session = sessionProvider.CreateSession(connection.Transport);
        var token = connection.ConnectionClosed;

        await HandleConnection(connection.Transport, session, token);
    }

    public async Task HandleConnection(IDuplexPipe pipe, FtpSession session, CancellationToken token)
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

                while (TryGetLine("\r\n"u8, buffer, out var position))
                {
                    var line = result.Buffer.Slice(0, position);
                    var (command, data) = FtpRequest.Parse(line);

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
                }
            }
            catch (OperationCanceledException)
            {
                break;
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

        // Generate temporary certificate
        await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = provider.GetCertificate(),
        }, token);

        return sslDuplex;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryGetLine(in ReadOnlySpan<byte> span, in ReadOnlySequence<byte> result, out SequencePosition position)
    {
        foreach (var buffer in result)
        {
            var index = buffer.Span.IndexOf(span);

            if (index == -1)
            {
                continue;
            }

            position = result.GetPosition(index + 2);
            return true;
        }

        position = default;
        return false;
    }
}
