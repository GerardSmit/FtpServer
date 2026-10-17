using System.Net;
using System.Net.Sockets;

namespace FtpServer;

/// <summary>
/// A reservation on a passive port. Disposing it returns the port to the pool and closes any
/// connection that arrived but was never claimed by a transfer command.
/// </summary>
public sealed class PassiveSocketOwner(IPAddress? targetAddress, PassiveSocket passiveSocket) : IDisposable
{
    private readonly TaskCompletionSource<Socket> _socketCompletionSource =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private int _disposed;

    public int Port => passiveSocket.Port;

    public Task<Socket> GetSocketAsync() => _socketCompletionSource.Task;

    /// <returns><c>true</c> when this owner took ownership of the socket.</returns>
    public bool SetSocket(Socket socket) => _socketCompletionSource.TrySetResult(socket);

    /// <summary>Wakes up a waiter when the listener is shutting down.</summary>
    public void Cancel() => _socketCompletionSource.TrySetCanceled();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        // Unregister first, so a connection arriving from here on finds no owner and is closed
        // by the accept loop instead of being handed to a session that has gone away.
        passiveSocket.Release(targetAddress, this);

        if (_socketCompletionSource.TrySetCanceled())
        {
            return;
        }

        // TrySetCanceled lost, so SetSocket won - but TrySetResult reserves the completion before
        // publishing the result, so the task may not read as completed yet. Without the wait both
        // sides drop the socket: the accept loop believes the owner took it, and vice versa.
        var task = _socketCompletionSource.Task;

        task.ContinueWith(
            static completed =>
            {
                if (completed.IsCompletedSuccessfully)
                {
                    try
                    {
                        completed.Result.Dispose();
                    }
                    catch
                    {
                        // Already closed.
                    }
                }
                else
                {
                    _ = completed.Exception;
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}
