using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
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
        var tasks = new List<Task>(_passiveSockets.Count);

        foreach (var passiveSocket in _passiveSockets.Values)
        {
            tasks.Add(passiveSocket.StopListeningAsync());
        }

        await Task.WhenAll(tasks);
    }

    public bool TryRent(IPAddress? targetAddress, [NotNullWhen(true)] out PassiveSocketOwner? socketOwner)
    {
        var range = options.Value.PassivePortRange;

        for (var port = range.Start; port <= range.End; port++)
        {
            if (!_passiveSockets.TryGetValue(port, out var passiveSocket))
            {
                passiveSocket = _passiveSockets.GetOrAdd(port, new PassiveSocket(port, logger));
            }

            if (passiveSocket.TryRent(targetAddress, out socketOwner))
            {
                return true;
            }
        }

        socketOwner = null;
        return false;
    }
}