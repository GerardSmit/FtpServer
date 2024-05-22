namespace FtpServer.Data;

public abstract class FtpDataMode
{
    public static readonly FtpDataModeActive Active = new();

    public abstract ValueTask<FtpStream> CreateDataChannelAsync(FtpSession session, CancellationToken token);
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
