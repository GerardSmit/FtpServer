using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace FtpServer;

public sealed class PassiveSocket(int port, ILogger<PassiveSocket> logger, TimeSpan? failureCooldown = null) : IAsyncDisposable
{
    /// <summary>
    /// How long a port that could not be bound, or stopped accepting, is left alone before it is
    /// tried again.
    /// </summary>
    public static readonly TimeSpan DefaultFailureCooldown = TimeSpan.FromMinutes(1);

    private readonly TimeSpan _failureCooldown = failureCooldown ?? DefaultFailureCooldown;

    private readonly ConcurrentDictionary<IPAddress, PassiveSocketOwner> _activeSockets = new();
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    private PassiveSocketOwner? _globalSocketOwner;
    private Task? _backgroundTask;

    /// <summary>
    /// <see cref="Environment.TickCount64"/> before which the port is not tried; zero when it is
    /// fine. A bind can fail for a reason that passes - the port briefly held by another process -
    /// so it is skipped for a while rather than for the life of the process.
    /// </summary>
    private long _unavailableUntil;

    public int Port => port;

    private bool IsCoolingDown => Environment.TickCount64 < Volatile.Read(ref _unavailableUntil);

    private void StartCooldown() =>
        Volatile.Write(ref _unavailableUntil, Environment.TickCount64 + Math.Max(1, (long)_failureCooldown.TotalMilliseconds));

    private async ValueTask<bool> EnsureListeningAsync()
    {
        if (IsCoolingDown)
        {
            return false;
        }

        // A loop that has ended counts as not listening, so a port that cooled down is bound again.
        if (Volatile.Read(ref _backgroundTask) is { IsCompleted: false })
        {
            return true;
        }

        await _semaphore.WaitAsync().ConfigureAwait(false);

        try
        {
            if (IsCoolingDown)
            {
                return false;
            }

            if (_backgroundTask is { IsCompleted: false })
            {
                return true;
            }

            _cancellationTokenSource.Token.ThrowIfCancellationRequested();

            var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                socket.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
                socket.Listen(10);
            }
            catch
            {
                // A failed bind must not leave the half-built listener to the finalizer.
                socket.Dispose();
                throw;
            }

            Volatile.Write(ref _backgroundTask, BackgroundTaskAsync(socket));
            return true;
        }
        catch (Exception e)
        {
            // Most likely the port is already in use; leave it alone for a while.
            StartCooldown();
            Log.CouldNotStartPassiveSocket(logger, e);
            return false;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public async Task StopListeningAsync()
    {
        await _semaphore.WaitAsync().ConfigureAwait(false);

        try
        {
            if (_backgroundTask is not { } task)
            {
                return;
            }

            await _cancellationTokenSource.CancelAsync();
            await task;
            _backgroundTask = null;
        }
        catch
        {
            // Shutdown is best effort.
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private const int MaxConsecutiveAcceptFailures = 20;

    private async Task BackgroundTaskAsync(Socket serverSocket)
    {
        var token = _cancellationTokenSource.Token;
        var consecutiveFailures = 0;

        try
        {
            while (!token.IsCancellationRequested)
            {
                Socket socket;

                try
                {
                    socket = await serverSocket.AcceptAsync(token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    // The listener was torn down underneath us.
                    break;
                }
                catch (SocketException ex)
                {
                    // A per-connection failure (a peer resetting while still in the backlog) says
                    // nothing about the listener; abandoning the loop would leave the port
                    // rentable but unable to accept.
                    Log.CouldNotAcceptPassiveSocket(logger, ex);

                    // A listener-level fault (descriptor exhaustion, ENOBUFS) fails instantly and
                    // repeatedly, so retrying without pause would spin a core and flood the log.
                    if (++consecutiveFailures >= MaxConsecutiveAcceptFailures)
                    {
                        break;
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(50), token).ConfigureAwait(false);
                    continue;
                }
                catch (Exception ex)
                {
                    Log.CouldNotAcceptPassiveSocket(logger, ex);
                    break;
                }

                consecutiveFailures = 0;

                if (!TryHandOff(socket))
                {
                    // Nobody is waiting for this connection - close it rather than leaking the socket.
                    Log.UnmatchedPassiveConnection(logger, (socket.RemoteEndPoint as IPEndPoint)?.Address);
                    try { socket.Dispose(); } catch { /* already gone */ }
                }
            }
        }
        finally
        {
            // Whatever ended the loop, this port can no longer accept. Cooling it down stops
            // TryRentAsync handing out a dead port ahead of every working one, and lets it back in
            // once the cause has had time to pass.
            StartCooldown();

            CancelOwners();

            try { serverSocket.Dispose(); } catch { /* already gone */ }
        }
    }

    private void CancelOwners()
    {
        Interlocked.Exchange(ref _globalSocketOwner, null)?.Cancel();

        foreach (var key in _activeSockets.Keys)
        {
            if (_activeSockets.TryRemove(key, out var socketOwner))
            {
                socketOwner.Cancel();
            }
        }
    }

    private bool TryHandOff(Socket socket)
    {
        var targetAddress = (socket.RemoteEndPoint as IPEndPoint)?.Address;

        if (targetAddress is not null)
        {
            if (_activeSockets.TryGetValue(targetAddress, out var socketOwner) && socketOwner.SetSocket(socket))
            {
                return true;
            }

            if (targetAddress.IsIPv4MappedToIPv6 &&
                _activeSockets.TryGetValue(targetAddress.MapToIPv4(), out socketOwner) &&
                socketOwner.SetSocket(socket))
            {
                return true;
            }
        }

        return Volatile.Read(ref _globalSocketOwner) is { } global && global.SetSocket(socket);
    }

    public async ValueTask<PassiveSocketOwner?> TryRentAsync(IPAddress? targetAddress)
    {
        if (!await EnsureListeningAsync().ConfigureAwait(false))
        {
            return null;
        }

        if (targetAddress is null)
        {
            var candidate = new PassiveSocketOwner(null, this);

            if (Interlocked.CompareExchange(ref _globalSocketOwner, candidate, null) is not null)
            {
                return null;
            }

            return candidate;
        }

        var owner = new PassiveSocketOwner(targetAddress, this);
        return _activeSockets.TryAdd(targetAddress, owner) ? owner : null;
    }

    /// <summary>
    /// Releases a rented slot. The owner is passed so a late release from an abandoned session
    /// cannot unregister the live owner that replaced it.
    /// </summary>
    public void Release(IPAddress? targetAddress, PassiveSocketOwner owner)
    {
        if (targetAddress is null)
        {
            Interlocked.CompareExchange(ref _globalSocketOwner, null, owner);
            return;
        }

        // Only removes the entry when it is still the one this owner registered.
        ((ICollection<KeyValuePair<IPAddress, PassiveSocketOwner>>)_activeSockets)
            .Remove(new KeyValuePair<IPAddress, PassiveSocketOwner>(targetAddress, owner));
    }

    public async ValueTask DisposeAsync()
    {
        await StopListeningAsync();
        _cancellationTokenSource.Dispose();
        _semaphore.Dispose();
    }
}
