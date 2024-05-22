using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using FtpServer.Options;
using Microsoft.Extensions.Options;

namespace FtpServer;

public class PassivePortProviderHostedService(PassivePortProvider passivePortProvider) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => passivePortProvider.StopAllAsync();
}

public class PassivePortProvider(IOptions<FtpOptions> options, IHostApplicationLifetime hostApplicationLifetime)
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

    public bool TryRent(IPAddress? targetAddress, [NotNullWhen(true)] out SocketOwner? socketOwner)
    {
        var range = options.Value.PassivePortRange;

        for (var port = range.Start; port <= range.End; port++)
        {
            if (!_passiveSockets.TryGetValue(port, out var passiveSocket))
            {
                passiveSocket = _passiveSockets.GetOrAdd(port, new PassiveSocket(port));
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

public class PassiveSocket(int port)
{
    private readonly ConcurrentDictionary<IPAddress, SocketOwner> _activeSockets = new();
    private readonly SemaphoreSlim _semaphore = new(1);
    private SocketOwner? _globalSocketOwner;
    private Task? _backgroundTask;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    public async Task<int> OpenPortAsync()
    {
        await StartListeningAsync();
        return port;
    }

    private async ValueTask StartListeningAsync()
    {
        if (_backgroundTask != null)
        {
            return;
        }

        await _semaphore.WaitAsync();

        try
        {
            _cancellationTokenSource.Token.ThrowIfCancellationRequested();

            if (_backgroundTask != null)
            {
                return;
            }

            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Any, port));
            socket.Listen(10);
            _backgroundTask = BackgroundTaskAsync(socket);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public async Task StopListeningAsync()
    {
        await _semaphore.WaitAsync();

        try
        {
            if (_backgroundTask == null)
            {
                return;
            }

            await _cancellationTokenSource.CancelAsync();
            await _backgroundTask;
            _backgroundTask = null;
        }
        catch
        {
            // Ignore
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task BackgroundTaskAsync(Socket serverSocket)
    {
        var token = _cancellationTokenSource.Token;

        while (!token.IsCancellationRequested)
        {
            try
            {
                var socket = await serverSocket.AcceptAsync(token);
                var targetAddress = (socket.RemoteEndPoint as IPEndPoint)?.Address;

                SetSocket(targetAddress, socket);
            }
            catch (TaskCanceledException)
            {
                break;
            }
            catch
            {
                 // TODO: Log
            }
        }

        CancelPassiveSockets();

        try
        {
            serverSocket.Dispose();
        }
        catch
        {
            // Ignore
        }
    }

    private void CancelPassiveSockets()
    {
        try
        {
            _globalSocketOwner?.Cancel();
        }
        catch
        {
            // Ignore
        }

        foreach (var socketOwner in _activeSockets.Values)
        {
            try
            {
                socketOwner.Cancel();
            }
            catch
            {
                // Ignore
            }
        }
    }

    private void SetSocket(IPAddress? targetAddress, Socket socket)
    {
        if (targetAddress == null)
        {
            _globalSocketOwner?.SetSocket(socket);
            return;
        }

        if (_activeSockets.TryGetValue(targetAddress, out var socketOwner))
        {
            socketOwner.SetSocket(socket);
            return;
        }

        if (targetAddress.IsIPv4MappedToIPv6 &&
            _activeSockets.TryGetValue(targetAddress.MapToIPv4(), out socketOwner))
        {
            socketOwner.SetSocket(socket);
            return;
        }

        _globalSocketOwner?.SetSocket(socket);
    }

    public bool TryRent(IPAddress? targetAddress, [NotNullWhen(true)] out SocketOwner? socketOwner)
    {
        // Global IP adres
        if (targetAddress == null)
        {
            if (_globalSocketOwner != null)
            {
                socketOwner = null;
                return false;
            }

            socketOwner = new SocketOwner(targetAddress, this);

            if (Interlocked.CompareExchange(ref _globalSocketOwner, socketOwner, null) != null)
            {
                socketOwner = null;
                return false;
            }

            return true;
        }

        // Specific IP adres
        if (_activeSockets.TryGetValue(targetAddress, out socketOwner))
        {
            socketOwner = null;
            return false;
        }

        socketOwner = new SocketOwner(targetAddress, this);

        if (!_activeSockets.TryAdd(targetAddress, socketOwner))
        {
            socketOwner = null;
            return false;
        }

        return true;
    }

    public void Release(IPAddress? targetAddress)
    {
        if (targetAddress == null)
        {
            _globalSocketOwner = null;
        }
        else
        {
            _activeSockets.TryRemove(targetAddress, out _);
        }
    }
}

public sealed class SocketOwner(IPAddress? targetAddress, PassiveSocket passiveSocket) : IDisposable
{
    private readonly TaskCompletionSource<Socket> _socketCompletionSource = new();

    public void Dispose()
    {
        passiveSocket.Release(targetAddress);
    }

    public Task<int> OpenPortAsync() => passiveSocket.OpenPortAsync();

    public Task<Socket> GetSocketAsync() => _socketCompletionSource.Task;

    public void SetSocket(Socket socket) => _socketCompletionSource.TrySetResult(socket);

    public void Cancel() => _socketCompletionSource.TrySetException(new OperationCanceledException());
}