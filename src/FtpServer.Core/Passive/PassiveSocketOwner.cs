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

    private const int Waiting = 0;
    private const int Claimed = 1;
    private const int Expired = 2;

    private int _disposed;
    private int _state;
    private Timer? _expiry;

    public int Port => passiveSocket.Port;

    /// <summary>True once <see cref="ExpireAfter"/> ran out before a transfer command claimed the port.</summary>
    public bool IsExpired => Volatile.Read(ref _state) == Expired;

    /// <summary>
    /// Gives the port back if no transfer command has <see cref="TryClaim">claimed</see> it by
    /// then. A PASV the client never follows up would otherwise hold its port until the session
    /// ends, and a handful of connections could drain a small range.
    /// </summary>
    public void ExpireAfter(TimeSpan timeout)
    {
        var timer = new Timer(static state => ((PassiveSocketOwner)state!).Expire(), this, timeout, Timeout.InfiniteTimeSpan);

        Volatile.Write(ref _expiry, timer);

        // Disposed or claimed while the timer was being created.
        if (Volatile.Read(ref _disposed) == 1 || Volatile.Read(ref _state) != Waiting)
        {
            StopExpiry();
        }
    }

    /// <summary>
    /// Takes the port for a transfer, ending the countdown of <see cref="ExpireAfter"/>.
    /// </summary>
    /// <returns><c>false</c> when the port has already expired.</returns>
    public bool TryClaim()
    {
        if (Interlocked.CompareExchange(ref _state, Claimed, Waiting) is not (Waiting or Claimed))
        {
            return false;
        }

        StopExpiry();
        return true;
    }

    private void Expire()
    {
        if (Interlocked.CompareExchange(ref _state, Expired, Waiting) == Waiting)
        {
            Dispose();
        }
    }

    private void StopExpiry() => Interlocked.Exchange(ref _expiry, null)?.Dispose();

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

        StopExpiry();

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
