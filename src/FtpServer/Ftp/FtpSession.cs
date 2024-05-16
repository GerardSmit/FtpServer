using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using FtpServer.Data;
using FtpServer.Kestrel.Utils;
using Zio;

namespace FtpServer;

public sealed class FtpSession(
    IDuplexPipe pipe,
    CertificateProvider certificateProvider,
    IFileSystem fileSystem
) : IDisposable
{
    public FtpDataMode Mode { get; set; } = FtpDataMode.Active;

    public UPath CurrentDirectory { get; set; } = UPath.Root;

    public int BufferSize { get; set; }

    public IPEndPoint? ActiveDataIp { get; set; }

    public CertificateProvider CertificateProvider => certificateProvider;

    public IFileSystem FileSystem { get; } = fileSystem;

    public Encoding Encoding { get; set; } = Encoding.ASCII;

    public IDuplexPipe Transport { get; set; } = pipe;

    public FtpDataConnectionMode DataConnectionMode { get; set; } = FtpDataConnectionMode.Clear;

    private ValueTask FlushAsync(CancellationToken token = default)
    {
        return Transport.Output.FlushAsync(token).GetAsValueTask();
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> data)
    {
        Transport.Output.Write(data);
        return FlushAsync();
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> data, ReadOnlySpan<byte> data2)
    {
        var buffer = Transport.Output.GetSpan(data.Length + data2.Length);
        data.CopyTo(buffer);
        data2.CopyTo(buffer.Slice(data.Length));
        Transport.Output.Advance(data.Length + data2.Length);
        return FlushAsync();
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> data, ReadOnlySpan<byte> data2, ReadOnlySpan<byte> data3)
    {
        var buffer = Transport.Output.GetSpan(data.Length + data2.Length + data3.Length);
        data.CopyTo(buffer);
        data2.CopyTo(buffer.Slice(data.Length));
        data3.CopyTo(buffer.Slice(data.Length + data2.Length));
        Transport.Output.Advance(data.Length + data2.Length + data3.Length);
        return FlushAsync();
    }
    public ValueTask WriteAsync(string data)
    {
        var buffer = Transport.Output.GetSpan(Encoding.GetMaxByteCount(data.Length));
        var length = Encoding.GetBytes(data, buffer);
        Transport.Output.Advance(length);
        return FlushAsync();
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> prefix, string value, ReadOnlySpan<byte> suffix, CancellationToken token = default)
    {
        var valueLength = Encoding.GetMaxByteCount(value.Length);

        if (valueLength > 100)
        {
            valueLength = Encoding.GetByteCount(value);
        }

        var maxLength = valueLength + prefix.Length + suffix.Length;
        var buffer = Transport.Output.GetSpan(maxLength);

        prefix.CopyTo(buffer);
        var length = Encoding.GetBytes(value, buffer.Slice(prefix.Length));
        suffix.CopyTo(buffer.Slice(prefix.Length + length));

        Transport.Output.Advance(prefix.Length + length + suffix.Length);

        return FlushAsync(token);
    }

    public void Dispose()
    {
        FileSystem.Dispose();
    }
}
