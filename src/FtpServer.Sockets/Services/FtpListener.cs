using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using Pipelines.Sockets.Unofficial;

namespace FtpServer.Services;

/// <summary>
/// Represents a multi-client socket-server capable of dispatching pipeline clients
/// </summary>
public abstract class FtpListener : IDisposable
{
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
        PipeOptions? receiveOptions = null)
    {
        if (_listener is not null)
        {
            throw new InvalidOperationException("Already listening");
        }

        addressFamily ??= endPoint.AddressFamily;

        var listener = new Socket(addressFamily.Value, socketType, protocolType);

        if (addressFamily.Value == AddressFamily.InterNetworkV6)
        {
            listener.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
        }

        listener.Bind(endPoint);
        listener.Listen(listenBacklog);

        _listener = listener;
        StartOnScheduler(
            receiveOptions?.ReaderScheduler,
            _ => FireAndForget(ListenForConnectionsAsync(sendOptions ?? PipeOptions.Default, receiveOptions ?? PipeOptions.Default)), null);

        OnStarted(endPoint);
    }

    /// <summary>
    /// Start listening as a server
    /// </summary>
    public void Listen(
        EndPoint endPoint,
        AddressFamily addressFamily,
        SocketType socketType,
        ProtocolType protocolType,
        PipeOptions sendOptions, PipeOptions receiveOptions)
        => Listen(endPoint, addressFamily, socketType, protocolType, 20, sendOptions, receiveOptions);

    /// <summary>
    /// Stop listening as a server
    /// </summary>
    public void Stop()
    {
        var socket = _listener;
        _listener = null;
        if (socket is not null)
        {
            try
            {
                socket.Dispose();
            }
            catch
            {
            }
        }
    }

    /// <summary>
    /// Release any resources associated with this instance
    /// </summary>
    public void Dispose()
    {
        Stop();
        Dispose(true);
    }

    /// <summary>
    /// Release any resources associated with this instance
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
    }

    private static void FireAndForget(Task? task)
    {
        // make sure that any exception is observed
        if (task is null) return;
        if (task.IsCompleted)
        {
            GC.KeepAlive(task.Exception);
            return;
        }

        task.ContinueWith(t => GC.KeepAlive(t.Exception), TaskContinuationOptions.OnlyOnFaulted);
    }

    /// <summary>
    /// Create a new instance of a socket server
    /// </summary>
    protected FtpListener(FtpSessionProvider sessionProvider)
    {
        // ReSharper disable once AsyncVoidLambda
        runClientAsync = async boxed =>
        {
            if (boxed is null)
            {
                return;
            }

            var connection = (SocketConnection)boxed;

            using var session = sessionProvider.CreateSession(connection);

            session.RemoteEndPoint = connection.Socket.RemoteEndPoint;
            session.LocalEndPoint = connection.Socket.LocalEndPoint;

            try
            {
                await OnClientConnectedAsync(session).ConfigureAwait(false);
                try
                {
                    session.Transport.Input.Complete();
                }
                catch
                {
                    // ignore
                }

                try
                {
                    session.Transport.Output.Complete();
                }
                catch
                {
                    // ignore
                }
            }
            catch (Exception ex)
            {
                try
                {
                    session.Transport.Input.Complete(ex);
                }
                catch
                {
                    // ignore
                }

                try
                {
                    session.Transport.Output.Complete(ex);
                }
                catch
                {
                    // ignore
                }

                OnClientFaulted(session, ex);
            }
            finally
            {
                if (session.Transport is IDisposable d)
                {
                    try
                    {
                        d.Dispose();
                    }
                    catch
                    {
                        // ignore
                    }
                }
            }
        };
    }

    private readonly Action<object?> runClientAsync;

    private static void StartOnScheduler(PipeScheduler? scheduler, Action<object?> callback, object? state)
    {
        if (scheduler == PipeScheduler.Inline) scheduler = null;
        (scheduler ?? PipeScheduler.ThreadPool).Schedule(callback, state);
    }

    private async Task ListenForConnectionsAsync(PipeOptions sendOptions, PipeOptions receiveOptions)
    {
        if (_listener is not { } listener)
        {
            throw new InvalidOperationException("Not listening");
        }

        try
        {
            while (true)
            {
                var clientSocket = await listener.AcceptAsync().ConfigureAwait(false);
                SocketConnection.SetRecommendedServerOptions(clientSocket);
                var pipe = SocketConnection.Create(clientSocket, sendOptions, receiveOptions);

                StartOnScheduler(receiveOptions.ReaderScheduler, runClientAsync, pipe);
            }
        }
        catch (NullReferenceException)
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
    /// Invoked when the server starts
    /// </summary>
    protected virtual void OnStarted(EndPoint endPoint)
    {
    }

    /// <summary>
    /// Invoked when a new client connects
    /// </summary>
    protected abstract Task OnClientConnectedAsync(FtpSession session);
}