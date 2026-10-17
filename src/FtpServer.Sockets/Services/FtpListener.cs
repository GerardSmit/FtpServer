using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using Pipelines.Sockets.Unofficial;

namespace FtpServer.Services;

/// <summary>
/// Represents a multi-client socket-server capable of dispatching pipeline clients
/// </summary>
public abstract class FtpListener(FtpSessionProvider sessionProvider, FtpConnectionLimiter limiter) : IDisposable
{
    private readonly Lock _gate = new();

    /// <summary>Live client tasks, so a stop can wait for them instead of abandoning them.</summary>
    private readonly HashSet<Task> _clients = [];

    private CancellationTokenSource _shutdown = new();

    /// <summary>
    /// Whether connections to this listener are implicit FTPS: TLS from the first byte, before
    /// the greeting. Set by <see cref="Listen"/>.
    /// </summary>
    protected bool ImplicitTls { get; private set; }
    private Task? _acceptLoop;
    private Socket? _listener;

    /// <summary>
    /// Start listening as a server
    /// </summary>
    public void Listen(
        EndPoint endPoint,
        AddressFamily? addressFamily = null,
        SocketType socketType = SocketType.Stream,
        ProtocolType protocolType = ProtocolType.Tcp,
        int listenBacklog = 20,
        PipeOptions? sendOptions = null,
        PipeOptions? receiveOptions = null,
        bool implicitTls = false)
    {
        if (_listener is not null)
        {
            throw new InvalidOperationException("Already listening");
        }

        ImplicitTls = implicitTls;

        addressFamily ??= endPoint.AddressFamily;

        var listener = new Socket(addressFamily.Value, socketType, protocolType);

        if (addressFamily.Value == AddressFamily.InterNetworkV6)
        {
            listener.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
        }

        listener.Bind(endPoint);
        listener.Listen(listenBacklog);

        _listener = listener;

        // Replaced rather than reused: a restart on the old, permanently cancelled source would
        // exit the accept loop at once while reporting that the server had started.
        if (_shutdown.IsCancellationRequested)
        {
            _shutdown.Dispose();
            _shutdown = new CancellationTokenSource();
        }

        _acceptLoop = Task.Run(() => ListenForConnectionsAsync(sendOptions ?? PipeOptions.Default, receiveOptions ?? PipeOptions.Default));

        OnStarted(endPoint);
    }

    /// <summary>
    /// Stop listening as a server
    /// </summary>
    public void Stop() => StopAsync().GetAwaiter().GetResult();

    /// <summary>
    /// Stops accepting and waits for the connections still being served to finish.
    /// </summary>
    /// <remarks>
    /// Without the wait, a stop returns while sessions are still writing to sockets the host is
    /// about to tear down, and a restart races a port that has not been released yet.
    /// </remarks>
    public async Task StopAsync()
    {
        var socket = _listener;
        _listener = null;

        try
        {
            await _shutdown.CancelAsync();
        }
        catch (ObjectDisposedException)
        {
            // Already disposed by a concurrent stop.
        }

        if (socket is not null)
        {
            try
            {
                socket.Dispose();
            }
            catch
            {
                // Already closed.
            }
        }

        if (_acceptLoop is { } acceptLoop)
        {
            _acceptLoop = null;

            try
            {
                await acceptLoop;
            }
            catch
            {
                // The loop reports its own faults through OnServerFaulted.
            }
        }

        Task[] clients;

        lock (_gate)
        {
            clients = [.. _clients];
        }

        foreach (var client in clients)
        {
            try
            {
                await client;
            }
            catch
            {
                // Each client's outcome has already been reported through OnClientFaulted.
            }
        }
    }

    public void Dispose()
    {
        Stop();
        _shutdown.Dispose();
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
    }

    private async Task ListenForConnectionsAsync(PipeOptions sendOptions, PipeOptions receiveOptions)
    {
        if (_listener is not { } listener)
        {
            throw new InvalidOperationException("Not listening");
        }

        try
        {
            while (!_shutdown.IsCancellationRequested)
            {
                var clientSocket = await listener.AcceptAsync(_shutdown.Token).ConfigureAwait(false);

                SocketConnection.SetRecommendedServerOptions(clientSocket);

                // Each client runs independently; a fault in one must not stop the accept loop.
                Track(Task.Run(() => RunClientAsync(clientSocket, sendOptions, receiveOptions)));
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            OnServerFaulted(ex);
        }
    }

    /// <summary>Registers a client task, and unregisters it when it finishes.</summary>
    private void Track(Task client)
    {
        lock (_gate)
        {
            _clients.Add(client);
        }

        _ = client.ContinueWith(
            static (completed, state) =>
            {
                var listener = (FtpListener)state!;

                lock (listener._gate)
                {
                    listener._clients.Remove(completed);
                }
            },
            this,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private async Task RunClientAsync(Socket clientSocket, PipeOptions sendOptions, PipeOptions receiveOptions)
    {
        // Enforced before any per-session resources are allocated.
        var lease = limiter.TryAcquire(clientSocket.RemoteEndPoint);

        if (lease is null)
        {
            try
            {
                OnConnectionRefused(clientSocket.RemoteEndPoint);
                await SendAndCloseAsync(clientSocket, "421 Too many connections, try again later.\r\n"u8.ToArray());
            }
            catch
            {
                // Nothing to do if even the refusal cannot be delivered - but the socket must
                // still be closed, including when the notification callback itself throws.
                try { clientSocket.Dispose(); } catch { /* already closed */ }
            }

            return;
        }

        SocketConnection? connection = null;
        FtpSession? session = null;

        try
        {
            // Until SocketConnection owns it, the raw socket is ours to close.
            connection = SocketConnection.Create(clientSocket, sendOptions, receiveOptions);

            // Constructing the session can fail (for example a misconfigured root), so it is
            // inside the try: an escaping exception here used to take down the process.
            session = sessionProvider.CreateSession(connection);
            session.RemoteEndPoint = connection.Socket.RemoteEndPoint;
            session.LocalEndPoint = connection.Socket.LocalEndPoint;

            await OnClientConnectedAsync(session, _shutdown.Token).ConfigureAwait(false);

            Complete(session, null);
        }
        catch (Exception ex)
        {
            if (session is not null)
            {
                Complete(session, ex);
                OnClientFaulted(session, ex);
            }
            else
            {
                OnServerFaulted(ex);
            }
        }
        finally
        {
            if (session is not null)
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }

            if (connection is not null)
            {
                // Disposes the real socket connection, which the session's Transport no longer
                // points at once the session has been upgraded to TLS.
                connection.Dispose();
            }
            else
            {
                // SocketConnection.Create never took ownership, so nothing else will close this.
                try { clientSocket.Dispose(); } catch { /* already closed */ }
            }

            lease.Dispose();
        }
    }

    private static async Task SendAndCloseAsync(Socket socket, byte[] message)
    {
        using (socket)
        {
            // A send may take only part of the buffer, leaving the client a truncated reply.
            var sent = 0;

            while (sent < message.Length)
            {
                var written = await socket.SendAsync(message.AsMemory(sent), SocketFlags.None).ConfigureAwait(false);

                if (written <= 0)
                {
                    break;
                }

                sent += written;
            }

            // Closing immediately after a send can discard the message. Shutting down the send
            // side flushes it and sends FIN; the peer's own close then confirms it was read.
            try
            {
                socket.Shutdown(SocketShutdown.Send);

                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                var scratch = new byte[64];

                while (await socket.ReceiveAsync(scratch, SocketFlags.None, timeout.Token).ConfigureAwait(false) > 0)
                {
                    // Drain whatever the client had already sent, until it closes.
                }
            }
            catch
            {
                // Timed out or already gone; the refusal has been sent either way.
            }
        }
    }

    private static void Complete(FtpSession session, Exception? exception)
    {
        try
        {
            session.Transport.Input.Complete(exception);
        }
        catch
        {
            // Already completed.
        }

        try
        {
            session.Transport.Output.Complete(exception);
        }
        catch
        {
            // Already completed.
        }
    }

    /// <summary>
    /// Invoked when the server has faulted
    /// </summary>
    protected virtual void OnServerFaulted(Exception exception)
    {
    }

    /// <summary>
    /// Invoked when a client has faulted
    /// </summary>
    protected virtual void OnClientFaulted(FtpSession client, Exception exception)
    {
    }

    /// <summary>
    /// Invoked when a connection is turned away because a limit was reached
    /// </summary>
    protected virtual void OnConnectionRefused(EndPoint? remoteEndPoint)
    {
    }

    /// <summary>
    /// Invoked when the server starts
    /// </summary>
    protected virtual void OnStarted(EndPoint endPoint)
    {
    }

    /// <summary>
    /// Invoked when a new client connects
    /// </summary>
    protected abstract Task OnClientConnectedAsync(FtpSession session, CancellationToken token);
}
