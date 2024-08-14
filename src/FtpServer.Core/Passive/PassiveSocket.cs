using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace FtpServer;

public class PassiveSocket(int port, ILogger<PassiveSocket> logger)
{
    private readonly ConcurrentDictionary<IPAddress, PassiveSocketOwner> _activeSockets = new();
    private readonly SemaphoreSlim _semaphore = new(1);
    private PassiveSocketOwner? _globalSocketOwner;
    private Task? _backgroundTask;
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    private bool _invalid;

    public int Port => port;

    private void StartListening()
    {
        if (_backgroundTask != null)
        {
            // Already listening
            return;
        }

        if (_invalid)
        {
            // Socket is invalid, don't start listening again
            return;
        }

        _semaphore.Wait();

        try
        {
            _cancellationTokenSource.Token.ThrowIfCancellationRequested();

            if (_backgroundTask != null)
            {
                return;
            }

            var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
            socket.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
            socket.Listen(10);
            _backgroundTask = BackgroundTaskAsync(socket);
        }
        catch (Exception e)
        {
            // Most likely the port is already in use
            _invalid = true;

            Log.CouldNotStartPassiveSocket(logger, e);
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
            catch (OperationCanceledException)
            {
                break;
            }
            catch(Exception ex)
            {
                Log.CouldNotAcceptPassiveSocket(logger, ex);
            }
        }

        CancelOwners();

        try
        {
            serverSocket.Dispose();
        }
        catch
        {
            // Ignore
        }
    }

    private void CancelOwners()
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

    public bool TryRent(IPAddress? targetAddress, [NotNullWhen(true)] out PassiveSocketOwner? socketOwner)
    {
        if (_invalid)
        {
            socketOwner = null;
            return false;
        }

        StartListening();

        // Global IP adres
        if (targetAddress == null)
        {
            if (_globalSocketOwner != null)
            {
                socketOwner = null;
                return false;
            }

            socketOwner = new PassiveSocketOwner(targetAddress, this);

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

        socketOwner = new PassiveSocketOwner(targetAddress, this);

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
