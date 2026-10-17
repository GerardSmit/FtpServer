namespace FtpServer;

/// <summary>
/// A parsed command line. <paramref name="Data"/> is the argument, verbatim after the single
/// separating space, with no line terminator.
/// </summary>
public readonly record struct FtpRequest(FtpCommand Command, ReadOnlyMemory<byte> Data)
{
    /// <summary>
    /// Splits a command line into its verb and argument. The caller supplies the line already
    /// stripped of its terminator and of any Telnet escapes.
    /// </summary>
    public static FtpRequest Parse(ReadOnlyMemory<byte> line)
    {
        var span = line.Span;

        // RFC 959 section 5.3.1: the verb is at most four characters, so anything longer
        // cannot be a command and would only waste time in the matcher.
        var spaceIndex = span.IndexOf((byte)' ');

        if (spaceIndex < 0)
        {
            return new FtpRequest(FtpCommandExtensions.FromUtf8(span), ReadOnlyMemory<byte>.Empty);
        }

        return new FtpRequest(
            FtpCommandExtensions.FromUtf8(span[..spaceIndex]),
            line[(spaceIndex + 1)..]);
    }

    /// <summary>
    /// Removes Telnet control sequences from a command line, in place.
    /// </summary>
    /// <remarks>
    /// The control connection is a Telnet NVT (RFC 959 section 4.1.2). Clients signal an urgent
    /// ABOR/STAT with IAC IP followed by IAC DM, and a literal 0xFF in an argument is doubled.
    /// Without this, those sequences are parsed as part of the verb.
    /// </remarks>
    /// <returns>The length of the sanitised line.</returns>
    public static int StripTelnet(Span<byte> line) => StripTelnet(line, out _);

    /// <param name="negotiation">
    /// The Telnet reply owed to the client, or null when nothing needs answering. RFC 1123
    /// section 4.1.2.12 requires an option request to be refused rather than ignored: a client
    /// that gets no answer may wait for one.
    /// </param>
    public static int StripTelnet(Span<byte> line, out byte[]? negotiation)
    {
        const byte IAC = 255;

        negotiation = null;

        var source = line.IndexOf(IAC);

        if (source < 0)
        {
            return line.Length;
        }

        List<byte>? replies = null;

        var destination = source;

        while (source < line.Length)
        {
            var current = line[source];

            if (current != IAC)
            {
                line[destination++] = current;
                source++;
                continue;
            }

            if (source + 1 >= line.Length)
            {
                // Trailing IAC with nothing after it - drop it.
                source++;
                continue;
            }

            var next = line[source + 1];

            if (next == IAC)
            {
                // Escaped literal 0xFF.
                line[destination++] = IAC;
                source += 2;
                continue;
            }

            const byte SB = 250;
            const byte SE = 240;

            if (next == SB)
            {
                // Subnegotiation runs until IAC SE, and the whole block is protocol, not data.
                // Treating SB as an ordinary two-byte command would copy its payload into the
                // command line.
                source += 2;

                while (source + 1 < line.Length && !(line[source] == IAC && line[source + 1] == SE))
                {
                    source++;
                }

                source = Math.Min(source + 2, line.Length);
                continue;
            }

            // Two-byte command (IP, DM, AYT, ...); three bytes when it carries an option code.
            if (next is >= 251 and <= 254)
            {
                const byte WILL = 251;
                const byte DO = 253;
                const byte WONT = 252;
                const byte DONT = 254;

                if (source + 2 < line.Length)
                {
                    // No Telnet option is supported, so every offer is declined and every request
                    // refused. WONT and DONT are already refusals and need no answer, which is
                    // what stops two peers refusing each other forever.
                    var reply = next switch
                    {
                        WILL => DONT,
                        DO => WONT,
                        _ => (byte)0,
                    };

                    if (reply != 0)
                    {
                        (replies ??= []).AddRange([IAC, reply, line[source + 2]]);
                    }
                }

                source += 3;
                continue;
            }

            source += 2;
        }

        negotiation = replies?.ToArray();
        return destination;
    }
}
