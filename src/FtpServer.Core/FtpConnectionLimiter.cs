using System.Collections.Concurrent;
using System.Net;
using FtpServer.Options;

namespace FtpServer;

/// <summary>
/// Caps how many control connections the server will serve, in total and per remote address.
/// </summary>
/// <remarks>
/// Without a cap a peer can open sockets until the process runs out of handles or memory; the
/// per-address limit stops one client monopolising the whole allowance.
/// </remarks>
public sealed class FtpConnectionLimiter(FtpOptionsProvider options)
{
    private readonly ConcurrentDictionary<string, int> _perAddress = new();
    private int _total;

    public Lease? TryAcquire(EndPoint? remoteEndPoint)
    {
        var limits = options.Current.Connection;
        var key = (remoteEndPoint as IPEndPoint)?.Address.ToString();

        if (limits.MaxConnections > 0)
        {
            if (Interlocked.Increment(ref _total) > limits.MaxConnections)
            {
                Interlocked.Decrement(ref _total);
                return null;
            }
        }
        else
        {
            Interlocked.Increment(ref _total);
        }

        if (key is not null && limits.MaxConnectionsPerAddress > 0)
        {
            var updated = _perAddress.AddOrUpdate(key, 1, static (_, current) => current + 1);

            if (updated > limits.MaxConnectionsPerAddress)
            {
                Release(key);
                return null;
            }
        }
        else if (key is not null)
        {
            _perAddress.AddOrUpdate(key, 1, static (_, current) => current + 1);
        }

        return new Lease(this, key);
    }

    private void Release(string? key)
    {
        Interlocked.Decrement(ref _total);

        if (key is null)
        {
            return;
        }

        // Remove the entry entirely when it drops to zero, so the dictionary does not grow
        // without bound as clients come and go.
        while (_perAddress.TryGetValue(key, out var current))
        {
            if (current <= 1)
            {
                if (((ICollection<KeyValuePair<string, int>>)_perAddress).Remove(new KeyValuePair<string, int>(key, current)))
                {
                    return;
                }

                continue;
            }

            if (_perAddress.TryUpdate(key, current - 1, current))
            {
                return;
            }
        }
    }

    public sealed class Lease(FtpConnectionLimiter limiter, string? key) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                limiter.Release(key);
            }
        }
    }
}
