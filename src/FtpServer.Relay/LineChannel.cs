using System.Text;

namespace FtpServer.Relay;

/// <summary>
/// An FTP control connection: lines in, lines out, as bytes, so what is relayed is relayed as it
/// came. Reads only what a line needs from its own buffer, so the stream can be replaced by a TLS
/// one after AUTH TLS without losing a byte.
/// </summary>
internal sealed class LineChannel(Stream stream)
{
    /// <summary>Longer than any command or reply line a server or client sends.</summary>
    private const int MaxLine = 64 * 1024;

    private readonly byte[] _buffer = new byte[16 * 1024];
    private int _start;
    private int _end;

    public Stream Stream { get; private set; } = stream;

    /// <summary>Whether bytes have arrived that no line was read for yet.</summary>
    public bool HasBuffered => _end > _start;

    /// <summary>Continues on <paramref name="replacement"/>, the same connection wrapped in TLS.</summary>
    public void Replace(Stream replacement)
    {
        if (HasBuffered)
        {
            throw new IOException("The server sent more before the TLS handshake.");
        }

        Stream = replacement;
    }

    /// <summary>The next line without its CRLF (or bare LF), or null when the connection closed.</summary>
    public async Task<byte[]?> ReadLineAsync(CancellationToken token)
    {
        var line = new MemoryStream();

        while (true)
        {
            var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);

            if (newline >= 0)
            {
                line.Write(_buffer, _start, newline - _start);
                _start = newline + 1;

                var bytes = line.ToArray();
                return bytes.Length > 0 && bytes[^1] == '\r' ? bytes[..^1] : bytes;
            }

            line.Write(_buffer, _start, _end - _start);
            _start = _end = 0;

            if (line.Length > MaxLine)
            {
                throw new IOException("A line is too long.");
            }

            var read = await Stream.ReadAsync(_buffer, token);

            if (read == 0)
            {
                return null;
            }

            _end = read;
        }
    }

    /// <summary>One reply, every line of it: "123-..." up to "123 ...". Null when the connection closed.</summary>
    public async Task<FtpReply?> ReadReplyAsync(CancellationToken token)
    {
        if (await ReadLineAsync(token) is not { } first)
        {
            return null;
        }

        var lines = new List<byte[]> { first };

        if (first.Length >= 4 && first[3] == '-')
        {
            var end = Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(first, 0, 3) + " ");

            while (true)
            {
                if (await ReadLineAsync(token) is not { } next)
                {
                    return null;
                }

                lines.Add(next);

                if (next.AsSpan().StartsWith(end))
                {
                    break;
                }
            }
        }

        return new FtpReply(lines);
    }

    public async Task WriteLineAsync(ReadOnlyMemory<byte> line, CancellationToken token)
    {
        var bytes = new byte[line.Length + 2];
        line.CopyTo(bytes);
        bytes[^2] = (byte)'\r';
        bytes[^1] = (byte)'\n';

        await Stream.WriteAsync(bytes, token);
        await Stream.FlushAsync(token);
    }

    public Task WriteLineAsync(string line, CancellationToken token) => WriteLineAsync(Encoding.UTF8.GetBytes(line), token);

    public async Task WriteReplyAsync(FtpReply reply, CancellationToken token)
    {
        foreach (var line in reply.Lines)
        {
            await WriteLineAsync(line, token);
        }
    }
}

/// <summary>A reply as it came, every line of it.</summary>
internal sealed record FtpReply(IReadOnlyList<byte[]> Lines)
{
    public string Code => Lines[0].Length >= 3 ? Encoding.ASCII.GetString(Lines[0], 0, 3) : "";

    /// <summary>1xx: the command was accepted and a transfer follows.</summary>
    public bool IsPreliminary => Code.StartsWith('1');

    public bool IsSuccess => Code.StartsWith('2');

    /// <summary>The text of the last line, after the code.</summary>
    public string Text => Lines[^1].Length > 4 ? Encoding.UTF8.GetString(Lines[^1], 4, Lines[^1].Length - 4) : "";

    public static FtpReply From(string line) => new([Encoding.UTF8.GetBytes(line)]);
}
