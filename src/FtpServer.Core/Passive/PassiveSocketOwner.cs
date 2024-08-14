using System.Net;
using System.Net.Sockets;

namespace FtpServer;

public sealed class PassiveSocketOwner(IPAddress? targetAddress, PassiveSocket passiveSocket) : IDisposable
{
    private readonly TaskCompletionSource<Socket> _socketCompletionSource = new();

    public void Dispose() => passiveSocket.Release(targetAddress);

    public int Port => passiveSocket.Port;

    public Task<Socket> GetSocketAsync() => _socketCompletionSource.Task;

    public void SetSocket(Socket socket) => _socketCompletionSource.TrySetResult(socket);

    public void Cancel() => _socketCompletionSource.TrySetException(new OperationCanceledException());
}
