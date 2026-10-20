using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpServer.Relay;

/// <summary>Accepts clients and runs a <see cref="RelaySession"/> for each.</summary>
internal sealed class RelayServer(IOptions<RelayOptions> options, ILoggerFactory loggers) : BackgroundService
{
    private readonly ILogger _logger = loggers.CreateLogger<RelayServer>();
    private readonly ConcurrentDictionary<Task, bool> _sessions = new();

    /// <summary>The port clients connect to; known once the relay listens (a configured 0 picks a free one).</summary>
    public int Port { get; private set; }

    private readonly TaskCompletionSource _listening = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task Listening => _listening.Task;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var relay = options.Value;
        var address = string.IsNullOrWhiteSpace(relay.ListenAddress) ? IPAddress.IPv6Any : IPAddress.Parse(relay.ListenAddress);
        var listener = new TcpListener(address, relay.Port);

        if (address.Equals(IPAddress.IPv6Any))
        {
            listener.Server.DualMode = true;
        }

        try
        {
            listener.Start();
        }
        catch (Exception ex)
        {
            _listening.TrySetException(ex);
            throw;
        }

        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _listening.TrySetResult();

        var ports = new PassivePorts(address, relay.PassivePortStart, relay.PassivePortEnd);
        var sessionLogger = loggers.CreateLogger<RelaySession>();

        _logger.LogInformation("Relaying FTP on {Address}:{Port} to {Host}:{Upstream} over TLS",
            address, Port, relay.Upstream.Host, relay.Upstream.Port);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;

                try
                {
                    client = await listener.AcceptTcpClientAsync(stoppingToken);
                }
                catch (SocketException ex)
                {
                    // One client's failed handshake must not stop the relay.
                    _logger.LogDebug(ex, "Accepting a client failed");
                    continue;
                }

                client.NoDelay = true;

                var session = Task.Run(() => new RelaySession(client, relay, ports, sessionLogger).RunAsync(stoppingToken), CancellationToken.None);
                _sessions[session] = true;
                _ = session.ContinueWith(done => _sessions.TryRemove(done, out _), TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
            await Task.WhenAll(_sessions.Keys);
        }
    }
}

public static class RelayServices
{
    /// <summary>A plain FTP listener for clients, with every connection relayed to the FTPS server.</summary>
    public static IServiceCollection AddFtpRelay(this IServiceCollection services, RelayOptions relay)
    {
        if (string.IsNullOrWhiteSpace(relay.Upstream.Host))
        {
            throw new InvalidOperationException("Relay:Upstream:Host is required: the FTPS server to relay to.");
        }

        if (relay.ListenAddress is { Length: > 0 } listen && !IPAddress.TryParse(listen, out _))
        {
            throw new InvalidOperationException("Relay:ListenAddress is not an IP address.");
        }

        // Fails here rather than for the first listing.
        Rewrites.Zone(relay.ListTimeZone);
        Rewrites.Zone(relay.Upstream.ListTimeZone);

        services.AddSingleton(Options.Create(relay));
        services.AddSingleton<RelayServer>();
        services.AddHostedService(provider => provider.GetRequiredService<RelayServer>());
        return services;
    }
}
