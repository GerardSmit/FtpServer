using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Zio;

namespace FtpServer.Extensions;

/// <summary>
/// Raised when an argument cannot be decoded. Carries the reply the client should get, so it is
/// answered as a syntax error rather than a server fault.
/// </summary>
public sealed class FtpArgumentException(string reply) : Exception(reply)
{
    /// <summary>Full FTP reply line, without the trailing CRLF.</summary>
    public string Reply { get; } = reply;
}

public static class SequenceExtensions
{
    /// <summary>
    /// Upper bound on a decoded argument. The connection handler already caps the command line,
    /// so this only guards the conversion helpers against being handed something unbounded.
    /// </summary>
    private const int MaxArgumentLength = 8 * 1024;

    public static bool SequenceEquals(this ReadOnlySequence<byte> sequence, ReadOnlySpan<byte> value)
    {
        if (sequence.Length != value.Length)
        {
            return false;
        }

        if (sequence.IsSingleSegment)
        {
            return sequence.FirstSpan.SequenceEqual(value);
        }

        Span<byte> buffer = stackalloc byte[128];
        byte[]? rented = null;

        if (value.Length > buffer.Length)
        {
            rented = ArrayPool<byte>.Shared.Rent(value.Length);
            buffer = rented;
        }

        try
        {
            var target = buffer[..value.Length];
            sequence.CopyTo(target);
            return target.SequenceEqual(value);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>Case-insensitive ASCII comparison, for keyword arguments such as "UTF8" or "ALL".</summary>
    public static bool EqualsIgnoreCase(this ReadOnlySequence<byte> sequence, ReadOnlySpan<byte> value)
    {
        if (sequence.Length != value.Length || sequence.Length > MaxArgumentLength)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[64];
        byte[]? rented = null;

        if (value.Length > buffer.Length)
        {
            rented = ArrayPool<byte>.Shared.Rent(value.Length);
            buffer = rented;
        }

        try
        {
            var target = buffer[..value.Length];
            sequence.CopyTo(target);

            for (var i = 0; i < target.Length; i++)
            {
                var a = target[i];
                var b = value[i];

                if (a is >= (byte)'a' and <= (byte)'z')
                {
                    a -= 32;
                }

                if (b is >= (byte)'a' and <= (byte)'z')
                {
                    b -= 32;
                }

                if (a != b)
                {
                    return false;
                }
            }

            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    public static bool TryGetInt32(this ReadOnlySequence<byte> sequence, out int value)
    {
        value = 0;

        if (sequence.Length is 0 or > 16)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[16];
        var target = buffer[..(int)sequence.Length];
        sequence.CopyTo(target);

        return int.TryParse(target, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    public static bool TryGetInt32(this ReadOnlySequence<byte> sequence, int min, int max, out int value)
    {
        if (!sequence.TryGetInt32(out value))
        {
            return false;
        }

        return value >= min && value <= max;
    }

    public static bool TryGetInt64(this ReadOnlySequence<byte> sequence, out long value)
    {
        value = 0;

        if (sequence.Length is 0 or > 24)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[24];
        var target = buffer[..(int)sequence.Length];
        sequence.CopyTo(target);

        return long.TryParse(target, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>Decodes an argument to a string.</summary>
    /// <remarks>
    /// An argument longer than <see cref="MaxArgumentLength"/> is refused rather than truncated,
    /// which would turn a pathname or password into a shorter value the client never sent.
    /// Invalid bytes are refused too: RFC 2640 section 3.1 requires a pathname to be checked for
    /// validity, and replacement would map every malformed sequence onto one name.
    /// </remarks>
    /// <exception cref="FtpArgumentException">The argument is too long or not valid text.</exception>
    public static string GetString(this ReadOnlySequence<byte> sequence, Encoding encoding)
    {
        if (sequence.IsEmpty)
        {
            return string.Empty;
        }

        if (sequence.Length > MaxArgumentLength)
        {
            throw new FtpArgumentException("501 Syntax error: argument too long.");
        }

        var length = (int)sequence.Length;
        var rented = ArrayPool<byte>.Shared.Rent(length);

        try
        {
            var target = rented.AsSpan(0, length);
            sequence.CopyTo(target);

            // RFC 2640 section 3.1: an embedded CR travels as CR NUL, the NUL being a wire escape.
            length = StripCrNul(target);

            try
            {
                return encoding.GetString(target[..length]);
            }
            catch (DecoderFallbackException)
            {
                throw new FtpArgumentException("501 Syntax error: argument is not valid text.");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>Collapses each CR NUL pair to the bare CR it encodes, in place.</summary>
    private static int StripCrNul(Span<byte> buffer)
    {
        var index = buffer.IndexOf((byte)'\r');

        if (index < 0 || index + 1 >= buffer.Length)
        {
            return buffer.Length;
        }

        var destination = index;

        for (var source = index; source < buffer.Length; source++)
        {
            buffer[destination++] = buffer[source];

            if (buffer[source] == (byte)'\r' && source + 1 < buffer.Length && buffer[source + 1] == 0)
            {
                source++;
            }
        }

        return destination;
    }

    // ---- path handling ----------------------------------------------------

    /// <summary>
    /// Resolves a client-supplied pathname against the session's working directory.
    /// </summary>
    /// <remarks>
    /// Normalisation happens here rather than in the file system: "." and ".." are folded away and
    /// ".." is clamped at the root, whatever the underlying file system would have done.
    /// </remarks>
    public static bool TryResolvePath(this ReadOnlySequence<byte> sequence, UPath current, Encoding encoding, out UPath result)
        => TryResolvePath(sequence.GetString(encoding), current, out result);

    public static bool TryResolvePath(string argument, UPath current, out UPath result)
    {
        result = current;

        // FTP clients quote pathnames that contain spaces.
        if (argument.Length >= 2 && argument[0] == '"' && argument[^1] == '"')
        {
            argument = argument[1..^1].Replace("\"\"", "\"");
        }

        if (argument.Length == 0)
        {
            return true;
        }

        var absolute = argument[0] is '/' or '\\';
        var segments = new List<string>();

        if (!absolute)
        {
            foreach (var segment in current.FullName.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                segments.Add(segment);
            }
        }

        foreach (var raw in argument.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (raw == ".")
            {
                continue;
            }

            if (raw == "..")
            {
                // Clamped rather than failed: "CWD .." from / is a no-op on every mainstream
                // server.
                if (segments.Count > 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }

                continue;
            }

            if (!IsValidSegment(raw))
            {
                return false;
            }

            segments.Add(raw);
        }

        result = segments.Count == 0 ? UPath.Root : new UPath("/" + string.Join('/', segments));
        return true;
    }

    private static bool IsValidSegment(string segment)
    {
        if (segment.Length == 0)
        {
            return false;
        }

        // Control characters cannot appear in a listing line without corrupting it, whatever the
        // host file system allows.
        foreach (var c in segment)
        {
            if (char.IsControl(c))
            {
                return false;
            }
        }

        if (!OperatingSystem.IsWindows())
        {
            // On Unix the characters below are ordinary filename bytes.
            return true;
        }

        // Windows strips a trailing dot or space, letting two distinct names address one file.
        if (segment[^1] is '.' or ' ')
        {
            return false;
        }

        foreach (var c in segment)
        {
            // ':' would open an alternate data stream; the rest are simply illegal.
            if (c is ':' or '*' or '?' or '"' or '<' or '>' or '|')
            {
                return false;
            }
        }

        return !IsReservedDeviceName(segment);
    }

    private static bool IsReservedDeviceName(string segment)
    {
        var dot = segment.IndexOf('.');
        var name = dot < 0 ? segment : segment[..dot];

        return name.ToUpperInvariant() switch
        {
            "CON" or "PRN" or "AUX" or "NUL" => true,
            ['C', 'O', 'M', >= '1' and <= '9'] => true,
            ['L', 'P', 'T', >= '1' and <= '9'] => true,
            _ => false,
        };
    }

    /// <summary>Escapes a pathname for a 257 reply: RFC 959 requires embedded quotes to be doubled.</summary>
    public static string ToQuotedPath(this UPath path) => path.FullName.Replace("\"", "\"\"");

    // ---- data port arguments ---------------------------------------------

    public static bool TryGetDataPort(this ReadOnlySequence<byte> data, [NotNullWhen(true)] out IPEndPoint? result)
    {
        result = null;

        if (data.Length is 0 or > 64)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[64];
        var target = buffer[..(int)data.Length];
        data.CopyTo(target);

        Span<int> parts = stackalloc int[6];
        var count = 0;

        foreach (var range in target.Split((byte)','))
        {
            if (count == 6)
            {
                // More than six fields: not a valid host-port.
                return false;
            }

            var field = target[range].Trim((byte)' ');

            if (!int.TryParse(field, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value is < 0 or > 255)
            {
                return false;
            }

            parts[count++] = value;
        }

        if (count != 6)
        {
            return false;
        }

        ReadOnlySpan<byte> ipBytes = [(byte)parts[0], (byte)parts[1], (byte)parts[2], (byte)parts[3]];
        var port = (parts[4] << 8) + parts[5];

        if (port is < 1 or > 65535)
        {
            return false;
        }

        result = new IPEndPoint(new IPAddress(ipBytes), port);
        return true;
    }

    public static bool TryGetIpAddress(this ReadOnlySequence<byte> data, [NotNullWhen(true)] out IPAddress? result)
    {
        result = null;

        // Longest textual IPv6 address, including a scope id, comfortably fits.
        if (data.Length is 0 or > 64)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[64];
        var target = buffer[..(int)data.Length];
        data.CopyTo(target);

        Span<char> chars = stackalloc char[64];
        var length = Encoding.UTF8.GetChars(target, chars);

        if (IPAddress.TryParse(chars[..length], out var ip))
        {
            result = ip;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Parses the RFC 2428 EPRT argument: <c>&lt;d&gt;net-prt&lt;d&gt;net-addr&lt;d&gt;tcp-port&lt;d&gt;</c>.
    /// </summary>
    public static bool TryGetExtendedPort(this ReadOnlySequence<byte> sequence, out IPEndPoint? result, out int networkProtocol)
    {
        result = null;
        networkProtocol = 0;

        if (sequence.Length is < 7 or > 128)
        {
            return false;
        }

        var reader = new SequenceReader<byte>(sequence);

        if (!reader.TryRead(out var delimiter))
        {
            return false;
        }

        // RFC 2428 section 2: the delimiter is a printable ASCII character in the range 33..126.
        if (delimiter is < 33 or > 126)
        {
            return false;
        }

        if (!reader.TryReadTo(out ReadOnlySequence<byte> protocolSequence, delimiter) ||
            !protocolSequence.TryGetInt32(out networkProtocol))
        {
            return false;
        }

        if (!reader.TryReadTo(out ReadOnlySequence<byte> addressSequence, delimiter))
        {
            return false;
        }

        if (!reader.TryReadTo(out ReadOnlySequence<byte> portSequence, delimiter))
        {
            // The trailing delimiter is mandatory.
            return false;
        }

        // Anything after the closing delimiter is not part of the argument.
        if (reader.Remaining != 0)
        {
            return false;
        }

        var expectedAddressFamily = networkProtocol switch
        {
            1 => AddressFamily.InterNetwork,
            2 => AddressFamily.InterNetworkV6,
            _ => AddressFamily.Unknown,
        };

        if (expectedAddressFamily == AddressFamily.Unknown)
        {
            // Signals the caller to answer 522 with the protocols we do support.
            return false;
        }

        if (!addressSequence.TryGetIpAddress(out var ipAddress) || ipAddress.AddressFamily != expectedAddressFamily)
        {
            return false;
        }

        if (!portSequence.TryGetInt32(min: 1, max: 65535, out var port))
        {
            return false;
        }

        result = new IPEndPoint(ipAddress, port);
        return true;
    }

    /// <summary>
    /// Parses the checksum-command argument: <c>&lt;pathname&gt;[ &lt;start&gt; &lt;end&gt;]</c>, also
    /// accepting the comma-separated form used by GlobalSCAPE and Serv-U.
    /// </summary>
    /// <param name="isFile">
    /// Reports whether a path names an existing file. When the whole argument does, it is taken as
    /// the pathname before any range is looked for, so "a,b.txt" and "report 2023" stay reachable.
    /// </param>
    public static bool TryGetChecksumRequest(this ReadOnlySequence<byte> sequence, UPath root, Encoding encoding, out ChecksumRequest request, Func<UPath, bool>? isFile = null)
    {
        request = default;

        var text = sequence.GetString(encoding);

        if (text.Length == 0)
        {
            return false;
        }

        // The range syntax is ambiguous with names that contain a comma or end in a number. An
        // existing file is the only reading that can be checked, so it wins.
        if (isFile is not null && TryResolvePath(text, root, out var whole) && isFile(whole))
        {
            request = new ChecksumRequest(whole, null, null);
            return true;
        }

        string pathPart;
        string? rangePart = null;

        if (text[0] == '"')
        {
            // Quoted pathname; the range, if any, follows the closing quote.
            var end = text.IndexOf('"', 1);

            if (end < 0)
            {
                return false;
            }

            pathPart = text[..(end + 1)];
            rangePart = text[(end + 1)..].Trim().TrimStart(',').Trim();
        }
        else
        {
            var comma = text.IndexOf(',');

            if (comma >= 0)
            {
                pathPart = text[..comma].Trim();
                rangePart = text[(comma + 1)..].Trim();
            }
            else
            {
                // Space-separated form: the range is the trailing one or two numeric fields.
                var fields = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                if (fields.Length >= 2 && long.TryParse(fields[^1], out _))
                {
                    var numeric = 1;

                    if (fields.Length >= 3 && long.TryParse(fields[^2], out _))
                    {
                        numeric = 2;
                    }

                    pathPart = string.Join(' ', fields[..^numeric]);
                    rangePart = string.Join(' ', fields[^numeric..]);
                }
                else
                {
                    pathPart = text;
                }
            }
        }

        if (!TryResolvePath(pathPart, root, out var path))
        {
            return false;
        }

        long? start = null;
        long? end2 = null;

        if (!string.IsNullOrWhiteSpace(rangePart))
        {
            var fields = rangePart.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries);

            switch (fields.Length)
            {
                case 1:
                    if (!long.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var only))
                    {
                        return false;
                    }

                    start = 0;
                    end2 = only;
                    break;

                case 2:
                    if (!long.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out var s) ||
                        !long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var e))
                    {
                        return false;
                    }

                    start = s;
                    end2 = e;
                    break;

                default:
                    return false;
            }

            if (start > end2)
            {
                return false;
            }
        }

        request = new ChecksumRequest(path, start, end2);
        return true;
    }
}

public readonly record struct ChecksumRequest(UPath Path, long? Start, long? End);
