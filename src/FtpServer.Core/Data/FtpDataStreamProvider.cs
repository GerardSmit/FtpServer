namespace FtpServer.Data;

public abstract class FtpDataStreamProvider
{
    public static readonly FtpDataStreamProviderActive Active = new();

    public abstract ValueTask<FtpStream> CreateDataChannelAsync(FtpSession session, CancellationToken token);

    /// <summary>
    /// Releases anything held on behalf of a data connection that was announced but never used —
    /// a rented passive port, its listening registration and any socket already accepted on it.
    /// </summary>
    public virtual ValueTask ReleaseAsync() => ValueTask.CompletedTask;
}

public abstract class FtpStream : IAsyncDisposable
{
    public abstract Stream Stream { get; }

    protected abstract ValueTask DisposeAsyncCore();

    public async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();
        GC.SuppressFinalize(this);
    }
}
