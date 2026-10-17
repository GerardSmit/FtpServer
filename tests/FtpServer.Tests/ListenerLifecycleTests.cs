using System.Net;
using System.Net.Sockets;
using FtpServer.Options;
using FtpServer.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer.Tests;

/// <summary>
/// Covers the socket listener's own lifecycle, which the protocol suite never stops and starts.
/// </summary>
public class ListenerLifecycleTests
{
    private static (IHost Host, FtpListener Listener, int Port) BuildListener(string root)
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)probe.LocalEndPoint!).Port;

        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Logging.SetMinimumLevel(LogLevel.None);

        builder.Services.AddFtpServer(options =>
        {
            options.Port = port;
            options.Path = root;
            options.Passive = false;
            options.Authentication.AllowAnonymous = true;
        });

        var host = builder.Build();
        return (host, host.Services.GetRequiredService<FtpListener>(), port);
    }

    [Fact]
    public async Task Listener_accepts_again_after_a_stop()
    {
        var root = Path.Combine(Path.GetTempPath(), "ftplistener-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);

        var (host, listener, port) = BuildListener(root);

        try
        {
            listener.Listen(new IPEndPoint(IPAddress.Loopback, port));

            await using (var client = new FtpTestClient(port))
            {
                await client.ConnectAsync();
                Assert.StartsWith("220", client.Banner);
            }

            await listener.StopAsync();

            // The one-shot cancellation token used to survive the stop, so a restarted listener
            // reported itself started while accepting nothing.
            listener.Listen(new IPEndPoint(IPAddress.Loopback, port));

            await using (var client = new FtpTestClient(port))
            {
                await client.ConnectAsync();
                Assert.StartsWith("220", client.Banner);
            }

            await listener.StopAsync();
        }
        finally
        {
            listener.Dispose();
            host.Dispose();

            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
                // Left for the OS to clean up.
            }
        }
    }

    [Fact]
    public async Task Stop_waits_for_the_sessions_still_being_served()
    {
        var root = Path.Combine(Path.GetTempPath(), "ftplistener-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);

        var (host, listener, port) = BuildListener(root);

        try
        {
            listener.Listen(new IPEndPoint(IPAddress.Loopback, port));

            await using var client = new FtpTestClient(port);
            await client.ConnectAsync();
            await client.SendAsync("USER anonymous");

            // Returning from the stop means every client task has finished.
            await listener.StopAsync();

            // Proof the port really was released: binding it again would fail otherwise.
            using var rebind = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            rebind.Bind(new IPEndPoint(IPAddress.Loopback, port));
        }
        finally
        {
            listener.Dispose();
            host.Dispose();

            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
                // Left for the OS to clean up.
            }
        }
    }
}
