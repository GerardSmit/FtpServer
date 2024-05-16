using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Text;
using Zio;

namespace FtpServer.Extensions;

public static class SequenceExtensions
{
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

        if (buffer.Length == 0)
        {
            return root;
        }

        if (buffer[0] == '/')
        {
            return new UPath(encoding.GetString(buffer));
        }

        var length = root.FullName.Length + buffer.Length + (root == UPath.Root ? 0 : 1);
        var path = string.Create(length, new Context(buffer, root, encoding), static (span, state) =>
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
}
