using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using FtpServer.Data;
using FtpServer.Utils;
using Zio;

namespace FtpServer;

public sealed class FtpSession(
    IDuplexPipe pipe,
    IServiceProvider provider,
    IFileSystem fileSystem
) : IDisposable
{
    public FtpDataStreamProvider DataStreamProvider { get; set; } = FtpDataStreamProvider.Active;

    public UPath CurrentDirectory { get; set; } = UPath.Root;

    public int BufferSize { get; set; }

    public IPEndPoint? ActiveDataIp { get; set; }

    public IServiceProvider RootServiceProvider { get; } = provider;

    public IFileSystem FileSystem { get; } = fileSystem;

    public Encoding Encoding { get; set; } = Encoding.ASCII;

    public IDuplexPipe Transport { get; set; } = pipe;

    public FtpDataConnectionMode DataConnectionMode { get; set; } = FtpDataConnectionMode.Clear;

    public EndPoint? RemoteEndPoint { get; set; }

    public EndPoint? LocalEndPoint { get; set; }

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

    public ValueTask WritePassiveModeAsync(ReadOnlySpan<byte> data, IPAddress address, int a, int b, ReadOnlySpan<byte> suffix, CancellationToken token = default)
    {
        var length = data.Length +
                     15 + // Max length of an IP address
                     5 + // Max length of a
                     5 + // Max length of b
                     suffix.Length;

        var buffer = Transport.Output.GetSpan(length);
        var span = buffer;
        data.CopyTo(span);

        var totalWritten = data.Length;
        span = span.Slice(data.Length);

        if (!address.TryFormat(span, out var written))
        {
            throw new InvalidOperationException("Failed to format IP address");
        }

        for (var i = 0; i < written; i++)
        {
            if (span[i] == '.')
            {
                span[i] = (byte)',';
            }
        }

        totalWritten += written;
        span = span.Slice(written);
        span[0] = (byte)',';

        if (!a.TryFormat(span.Slice(1), out written))
        {
            throw new InvalidOperationException("Failed to format port number");
        }

        totalWritten += written + 1;
        span = span.Slice(written + 1);
        span[0] = (byte)',';

        if (!b.TryFormat(span.Slice(1), out written))
        {
            throw new InvalidOperationException("Failed to format port number");
        }

        totalWritten += written + 1;
        span = span.Slice(written + 1);

        suffix.CopyTo(span);
        totalWritten += suffix.Length;

        Transport.Output.Advance(totalWritten);
        return FlushAsync(token);
    }

    public ValueTask WriteExtendedPassiveModeAsync(ReadOnlySpan<byte> data, int port, ReadOnlySpan<byte> suffix, CancellationToken token = default)
    {
        // |||port|
        var length = data.Length +
                     3 + // Delimiters (3)
                     4 + // Max length of port
                     1 + // Delimiter (1)
                     suffix.Length;

        var buffer = Transport.Output.GetSpan(length);
        var span = buffer;
        data.CopyTo(span);

        var totalWritten = data.Length;
        span = span.Slice(data.Length);

        span[0] = (byte)'|';
        span[1] = (byte)'|';
        span[2] = (byte)'|';

        totalWritten += 3;
        span = span.Slice(3);

        if (!port.TryFormat(span, out var written))
        {
            throw new InvalidOperationException("Failed to format port number");
        }

        totalWritten += written;
        span = span.Slice(written);

        span[0] = (byte)'|';
        suffix.CopyTo(span.Slice(1));
        totalWritten += suffix.Length + 1;

        Transport.Output.Advance(totalWritten);
        return FlushAsync(token);
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
