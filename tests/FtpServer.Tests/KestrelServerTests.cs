using System.Net;
using System.Net.Sockets;
using System.Text;
using FtpServer.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FtpServer.Tests;

/// <summary>
/// Runs the server behind Kestrel rather than the raw socket listener.
/// </summary>
/// <remarks>
/// Both front-ends run the same connection handler, so the socket suite covers the protocol. What
/// only this suite can prove is that the Kestrel transport is wired up: connections reach the
/// handler, the limiter applies, and a disconnect tears the session down.
/// </remarks>
public sealed class KestrelFixture : IAsyncDisposable
{
    private readonly WebApplication _app;

    public string Root { get; }

    public int Port { get; }

    private KestrelFixture(WebApplication app, string root, int port)
    {
        _app = app;
        Root = root;
        Port = port;
    }

    public static async Task<KestrelFixture> StartAsync(Action<FtpOptions>? configure = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "ftpkestrel-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);

        var port = ReservePort();

        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.Logging.SetMinimumLevel(LogLevel.None);

        builder.Services.AddFtpServerCore(options =>
        {
            options.Port = port;
            options.Path = root;

            // Active mode only: a passive range would need reserving per fixture, and the data
            // channel is shared code the socket suite already covers.
            options.Passive = false;
            options.Authentication.AllowAnonymous = true;
            options.Authentication.AnonymousCanWrite = true;
            options.Authentication.FailureDelay = TimeSpan.Zero;

            configure?.Invoke(options);
        });

        builder.WebHost.UseKestrel(kestrel => kestrel.AddFtpServer());

        var app = builder.Build();
        await app.StartAsync();

        return new KestrelFixture(app, root, port);
    }

    private static int ReservePort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    public string WriteFile(string relativePath, string content)
    {
        var full = Path.Combine(Root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content);
        return full;
    }

    public async Task<FtpTestClient> ConnectAsync()
    {
        var client = new FtpTestClient(Port);
        await client.ConnectAsync();
        return client;
    }

    public async Task<FtpTestClient> LoginAsync()
    {
        var client = await ConnectAsync();
        await client.SendAsync("USER anonymous");
        await client.SendAsync("PASS a@b.c");
        return client;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync(TimeSpan.FromSeconds(5));
        await _app.DisposeAsync();

        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
            // Left for the OS to clean up.
        }
    }
}

public class KestrelServerTests
{
    [Fact]
    public async Task Connection_reaches_the_shared_command_handler()
    {
        await using var server = await KestrelFixture.StartAsync();
        server.WriteFile("readme.txt", "kestrel");

        await using var client = await server.LoginAsync();

        Assert.StartsWith("220", client.Banner);
        Assert.Contains("\"/\"", await client.SendAsync("PWD"), StringComparison.Ordinal);
        Assert.StartsWith("213", await client.SendAsync("MDTM readme.txt"));
        Assert.StartsWith("215", await client.SendAsync("SYST"));
    }

    [Fact]
    public async Task Data_transfer_works_over_the_kestrel_transport()
    {
        await using var server = await KestrelFixture.StartAsync();
        server.WriteFile("readme.txt", "kestrel payload");

        await using var client = await server.LoginAsync();
        await client.SendAsync("TYPE I");

        // Active mode: the server dials back to a listener this test owns.
        var (data, control) = await client.DownloadActiveAsync("RETR readme.txt");

        Assert.Contains("226", control, StringComparison.Ordinal);
        Assert.Equal("kestrel payload", Encoding.ASCII.GetString(data));
    }

    [Fact]
    public async Task Root_containment_applies_to_this_front_end_too()
    {
        await using var server = await KestrelFixture.StartAsync();

        await using var client = await server.LoginAsync();

        // The jail comes from the shared session provider, so ".." is clamped here too.
        Assert.StartsWith("250", await client.SendAsync("CWD /../.."));
        Assert.Contains("\"/\"", await client.SendAsync("PWD"), StringComparison.Ordinal);

        Assert.StartsWith("550", await client.SendAsync("RETR ../../../etc/passwd"));
    }

    [Fact]
    public async Task Connection_limit_is_enforced()
    {
        await using var server = await KestrelFixture.StartAsync(
            options => options.Connection.MaxConnections = 1);

        await using var first = await server.ConnectAsync();

        await using var second = new FtpTestClient(server.Port);
        await second.ConnectAsync();

        Assert.StartsWith("421", second.Banner);
    }

    [Fact]
    public async Task Client_disconnect_does_not_fault_the_server()
    {
        await using var server = await KestrelFixture.StartAsync();
        server.WriteFile("readme.txt", "still here");

        var abandoned = await server.LoginAsync();
        await abandoned.SendAsync("CWD /");
        await abandoned.DisposeAsync();

        // A dropped connection must not take the listener with it.
        await using var client = await server.LoginAsync();

        Assert.StartsWith("213", await client.SendAsync("SIZE readme.txt"));
    }
}
