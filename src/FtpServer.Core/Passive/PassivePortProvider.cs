using System.Collections.Concurrent;
using System.Net;
using FtpServer.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpServer;

public class PassivePortProvider(IOptions<FtpOptions> options, ILogger<PassiveSocket> logger)
{
    private readonly ConcurrentDictionary<int, PassiveSocket> _passiveSockets = new();

    public async Task StopAllAsync()
    {
        var tasks = new List<ValueTask>(_passiveSockets.Count);

        foreach (var passiveSocket in _passiveSockets.Values)
        {
            // DisposeAsync stops the listener and then releases its semaphore and token source,
            // which StopListeningAsync alone would leave behind.
            tasks.Add(passiveSocket.DisposeAsync());
        }

        foreach (var task in tasks)
        {
            try
            {
                await task;
            }
            catch
            {
                // Shutdown is best effort.
            }
        }

        _passiveSockets.Clear();
    }

    /// <summary>
    /// Reserves a port for a data connection expected from <paramref name="targetAddress"/>.
    /// </summary>
    public async ValueTask<PassiveSocketOwner?> TryRentAsync(IPAddress? targetAddress)
    {
        var range = options.Value.PassivePortRange;
        var count = range.End - range.Start + 1;

        // Scanning from a random position keeps the next data port unpredictable; from the bottom
        // of the range, a quiet server hands nearly every transfer the same port to race for.
        var offset = Random.Shared.Next(count);

        for (var i = 0; i < count; i++)
        {
            var port = range.Start + (offset + i) % count;

            // GetOrAdd with a factory avoids constructing a PassiveSocket on every probe.
            var passiveSocket = _passiveSockets.GetOrAdd(
                port,
                static (p, state) => new PassiveSocket(p, state),
                logger);

            if (await passiveSocket.TryRentAsync(targetAddress).ConfigureAwait(false) is { } owner)
            {
                return owner;
            }
        }

        return null;
    }
}
