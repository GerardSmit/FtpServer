using System.Buffers;
using System.Runtime.CompilerServices;

namespace FtpServer;

public readonly record struct FtpRequest(FtpCommand Command, ReadOnlySequence<byte> Data)
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static FtpRequest Parse(ReadOnlySequence<byte> line)
    {
        return line.IsSingleSegment ? ParseMemory(line.First) : ParseSequence(line);
    }

    private static FtpRequest ParseSequence(ReadOnlySequence<byte> line)
    {
        var reader = new SequenceReader<byte>(line);

        FtpCommand command;
        ReadOnlySequence<byte> data;

        if (reader.TryReadTo(out ReadOnlySequence<byte> commandBytes, (byte)' '))
        {
            Span<byte> commandSpan = stackalloc byte[(int)commandBytes.Length];
            commandBytes.CopyTo(commandSpan);

            command = FtpCommandExtensions.FromUtf8(commandSpan);
            data = reader.UnreadSequence.Slice(0, reader.Remaining - 2);
        }
        else
        {
            Span<byte> commandSpan = stackalloc byte[(int)line.Length - 2];

            line.CopyTo(commandSpan);

            command = FtpCommandExtensions.FromUtf8(commandSpan);
            data = ReadOnlySequence<byte>.Empty;
        }

        return new FtpRequest(command, data);
    }

    private static FtpRequest ParseMemory(ReadOnlyMemory<byte> memory)
    {
        var span = memory.Span;
        var spaceIndex = span.IndexOf((byte)' ');

        FtpCommand command;
        ReadOnlySequence<byte> data;

        if (spaceIndex == -1)
        {
            command = FtpCommandExtensions.FromUtf8(span.Slice(0, span.Length - 2));
            data = ReadOnlySequence<byte>.Empty;
        }
        else
        {
            var commandData = memory.Slice(spaceIndex + 1, span.Length - spaceIndex - 3);

            command = FtpCommandExtensions.FromUtf8(span.Slice(0, spaceIndex));
            data = new ReadOnlySequence<byte>(commandData);
        }

        return new FtpRequest(command, data);
    }
}
