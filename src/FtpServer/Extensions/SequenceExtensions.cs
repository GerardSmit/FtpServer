using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Zio;

namespace FtpServer.Extensions;

public static class SequenceExtensions
{
    public static bool SequenceEquals(this ReadOnlySequence<byte> sequence, ReadOnlySpan<byte> value)
    {
        if (sequence.Length != value.Length)
        {
            return false;
        }

        if (sequence.IsSingleSegment)
        {
            return sequence.First.Span.SequenceEqual(value);
        }

        Span<byte> buffer = stackalloc byte[(int)sequence.Length];
        sequence.CopyTo(buffer);
        return buffer.SequenceEqual(value);
    }

    public static bool TryGetInt32(this ReadOnlySequence<byte> sequence, out int value)
    {
        if (sequence.IsSingleSegment)
        {
            return int.TryParse(sequence.First.Span, NumberStyles.None, CultureInfo.InvariantCulture, out value);
        }

        Span<byte> buffer = stackalloc byte[(int)sequence.Length];
        sequence.CopyTo(buffer);
        return int.TryParse(buffer, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    public static bool TryGetInt32(this ReadOnlySequence<byte> sequence, int min, int max, out int value)
    {
        if (!sequence.TryGetInt32(out value))
        {
            return false;
        }

        return value >= min && value <= max;
    }

    public static unsafe UPath GetUPath(this ReadOnlySequence<byte> sequence, UPath root, Encoding encoding)
    {
        scoped ReadOnlySpan<byte> buffer;

        if (sequence.IsSingleSegment)
        {
            buffer = sequence.First.Span;
        }
        else
        {
            Span<byte> temp = stackalloc byte[(int)sequence.Length];
            sequence.CopyTo(temp);
            buffer = temp;
        }

        return ToUPath(buffer, root, encoding);
    }

    public static UPath ToUPath(this in ReadOnlySpan<byte> buffer, UPath root, Encoding encoding)
    {
        if (buffer.Length == 0)
        {
            return root;
        }

        var span = buffer[0] == '"' && buffer[^1] == '"'
            ? buffer.Slice(1, buffer.Length - 2)
            : buffer;

        if (span[0] == '/')
        {
            return new UPath(encoding.GetString(span));
        }

        var length = root.FullName.Length + span.Length + (root == UPath.Root ? 0 : 1);
        var path = string.Create(length, new Context(span, root, encoding), static (span, state) =>
        {
            var root = state.Root;
            int index;

            if (root != UPath.Root)
            {
                root.FullName.AsSpan().CopyTo(span);
                index = root.FullName.Length;
            }
            else
            {
                index = 0;
            }

            span[index] = '/';
            state.Encoding.GetChars(state.Buffer, span.Slice(index + 1));
        });

        return new UPath(path);
    }

#pragma warning disable CS8500
#pragma warning disable CS9113
    private readonly unsafe struct Context(ReadOnlySpan<byte> buffer, UPath root, Encoding encoding)
    {
        private readonly nint _buffer = (nint)(&buffer);

        public UPath Root { get; } = root;

        public Encoding Encoding { get; } = encoding;

        public ReadOnlySpan<byte> Buffer => *(ReadOnlySpan<byte>*)_buffer;
    }
#pragma warning restore CS9113
#pragma warning restore CS8500

    public static bool TryGetDataPort(this ReadOnlySequence<byte> data, [NotNullWhen(true)] out IPEndPoint? result)
    {
        var reader = new SequenceReader<byte>(data);

        if (!GetValue(ref reader, out var ip1) ||
            !GetValue(ref reader, out var ip2) ||
            !GetValue(ref reader, out var ip3) ||
            !GetValue(ref reader, out var ip4) ||
            !GetValue(ref reader, out var port1) ||
            !reader.UnreadSequence.TryGetInt32(min: 0, max: 255, out var port2))
        {
            result = default;
            return false;
        }

        ReadOnlySpan<byte> ipBytes = [(byte)ip1, (byte)ip2, (byte)ip3, (byte)ip4];
        var ip = new IPAddress(ipBytes);
        var port = (port1 << 8) + port2;

        result = new IPEndPoint(ip, port);
        return true;

        static bool GetValue(ref SequenceReader<byte> reader, out int result)
        {
            if (!reader.TryReadTo(out ReadOnlySequence<byte> sequence, (byte)','))
            {
                result = 0;
                return false;
            }

            return sequence.TryGetInt32(min: 0, max: 255, out result);
        }
    }

    public static bool TryGetIpAddress(this ReadOnlySequence<byte> data, [NotNullWhen(true)] out IPAddress? result)
    {
        Span<char> buffer = stackalloc char[39];

        int length;

        if (data.IsSingleSegment)
        {
            length = Encoding.UTF8.GetChars(data.First.Span, buffer);
        }
        else
        {
            Span<byte> temp = stackalloc byte[(int)data.Length];
            data.CopyTo(temp);
            length = Encoding.UTF8.GetChars(temp, buffer);
        }

        if (IPAddress.TryParse(buffer.Slice(0, length), out var ip))
        {
            result = ip;
            return true;
        }

        result = default;
        return false;
    }

    public static bool TryGetXCRC(this ReadOnlySequence<byte> sequence, UPath root, Encoding encoding, out Crc32Request request)
    {
        scoped ReadOnlySpan<byte> buffer;

        if (sequence.IsSingleSegment)
        {
            buffer = sequence.First.Span;
        }
        else
        {
            Span<byte> temp = stackalloc byte[(int)sequence.Length];
            sequence.CopyTo(temp);
            buffer = temp;
        }

        var commaIndex = buffer.IndexOf((byte)',');

        if (commaIndex == -1)
        {
            // XCRC <File Name>
            request = new Crc32Request(buffer.ToUPath(root, encoding), default, default);
            return true;
        }

        var path = buffer.Slice(0, commaIndex).ToUPath(root, encoding);
        var range = buffer.Slice(commaIndex + 1);

        commaIndex = range.IndexOf((byte)',');

        if (commaIndex == -1)
        {
            // XCRC <File Name>, <EP>
            if (!int.TryParse(range.Trim((byte)' '), NumberStyles.None, CultureInfo.InvariantCulture, out var end))
            {
                request = default;
                return false;
            }

            request = new Crc32Request(path, default, end);
            return true;
        }

        // XCRC <File Name>, <SP>, <EP>
        if (!int.TryParse(range.Slice(0, commaIndex).Trim((byte)' '), NumberStyles.None, CultureInfo.InvariantCulture, out var startValue) ||
            !int.TryParse(range.Slice(commaIndex + 1).Trim((byte)' '), NumberStyles.None, CultureInfo.InvariantCulture, out var endValue))
        {
            request = default;
            return false;
        }

        request = new Crc32Request(path, startValue, endValue);
        return true;
    }

    public static bool TryGetExtendedPort(this ReadOnlySequence<byte> sequence, [NotNullWhen(true)] out IPEndPoint? result)
    {
        var reader = new SequenceReader<byte>(sequence);

        if (!reader.TryRead(out var d))
        {
            result = default;
            return false;
        }

        if (!reader.TryReadTo(out ReadOnlySequence<byte> netPrtSequence, d) ||
            !netPrtSequence.TryGetInt32(out var netPrt))
        {
            result = default;
            return false;
        }

        if (!reader.TryReadTo(out ReadOnlySequence<byte> netAddrSequence, d) ||
            !netAddrSequence.TryGetIpAddress(out var ipAddress))
        {
            result = default;
            return false;
        }

        var expectedAddressFamily = netPrt switch
        {
            1 => AddressFamily.InterNetwork,
            2 => AddressFamily.InterNetworkV6,
            _ => AddressFamily.Unknown
        };

        if (ipAddress.AddressFamily != expectedAddressFamily)
        {
            result = default;
            return false;
        }


        if (!reader.TryReadTo(out ReadOnlySequence<byte> portSequence, d) ||
            !portSequence.TryGetInt32(out var port))
        {
            result = default;
            return false;
        }

        result = new IPEndPoint(ipAddress, port);
        return true;
    }
}

public record struct Crc32Request(UPath Path, int? Start, int? End);
