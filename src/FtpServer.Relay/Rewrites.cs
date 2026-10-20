using System.Globalization;
using System.Text;

namespace FtpServer.Relay;

/// <summary>What the relay changes on the way through; everything else passes as it came.</summary>
internal static class Rewrites
{
    private const string CompleteDate = "MMM dd HH:mm:ss yyyy";

    /// <summary>
    /// LIST with -T added, so the server gives every time with seconds and year: "LIST -R /a" becomes
    /// "LIST -RT /a", "LIST" becomes "LIST -T".
    /// </summary>
    public static string ListWithCompleteTimes(string argument)
    {
        var trimmed = argument.Trim();

        if (trimmed.StartsWith('-'))
        {
            var flagsEnd = trimmed.IndexOf(' ') is >= 0 and var space ? space : trimmed.Length;
            var flags = trimmed[..flagsEnd];

            return flags.Contains('T')
                ? $"LIST {trimmed}"
                : $"LIST {flags}T{trimmed[flagsEnd..]}";
        }

        return trimmed.Length == 0 ? "LIST -T" : $"LIST -T {trimmed}";
    }

    /// <summary>
    /// The server's features without what the relay does not pass on: TLS (the client side is plain)
    /// and, unless offered, MLSD and MLST.
    /// </summary>
    public static FtpReply Features(FtpReply reply, bool offerMlsd)
    {
        if (reply.Code != "211")
        {
            return reply;
        }

        var hidden = offerMlsd ? new[] { "AUTH", "PBSZ", "PROT", "CCC" } : ["AUTH", "PBSZ", "PROT", "CCC", "MLSD", "MLST"];

        return new FtpReply(reply.Lines.Where(line =>
        {
            var text = Encoding.ASCII.GetString(line).Trim();
            var feature = text.Split(' ', 2)[0];
            return line.Length == 0 || line[0] != ' ' || !hidden.Contains(feature, StringComparer.OrdinalIgnoreCase);
        }).ToList());
    }

    /// <summary>
    /// Copies a LIST answer, its times converted from the server's zone to the client's. Only the four
    /// date fields of a line change; a line without a complete time (or no listing line at all, such
    /// as a "/path:" header) passes as it came.
    /// </summary>
    public static async Task CopyListingAsync(Stream source, Stream destination, TimeZoneInfo from, TimeZoneInfo to, CancellationToken token)
    {
        var buffer = new byte[64 * 1024];
        var pending = new MemoryStream();

        while (true)
        {
            var read = await source.ReadAsync(buffer, token);

            if (read == 0)
            {
                break;
            }

            var start = 0;

            for (var i = 0; i < read; i++)
            {
                if (buffer[i] != '\n')
                {
                    continue;
                }

                pending.Write(buffer, start, i + 1 - start);
                start = i + 1;

                var line = Convert(pending.ToArray(), from, to);
                await destination.WriteAsync(line, token);
                pending.SetLength(0);
            }

            pending.Write(buffer, start, read - start);
        }

        if (pending.Length > 0)
        {
            await destination.WriteAsync(Convert(pending.ToArray(), from, to), token);
        }

        await destination.FlushAsync(token);
    }

    /// <summary>"drwxr-xr-x 2 ftp ftp 4096 Oct 07 11:45:43 2026 name": fields 6 to 9 are the time.</summary>
    internal static byte[] Convert(byte[] line, TimeZoneInfo from, TimeZoneInfo to)
    {
        var bounds = new (int Start, int End)[9];
        var position = 0;

        for (var field = 0; field < bounds.Length; field++)
        {
            while (position < line.Length && line[position] == ' ')
            {
                position++;
            }

            var end = Array.IndexOf(line, (byte)' ', position);

            if (end < 0)
            {
                return line;
            }

            bounds[field] = (position, end);
            position = end;
        }

        var dateStart = bounds[5].Start;
        var dateEnd = bounds[8].End;
        var text = Encoding.ASCII.GetString(line, dateStart, dateEnd - dateStart);

        if (!DateTime.TryParseExact(text, ["MMM dd HH:mm:ss yyyy", "MMM d HH:mm:ss yyyy"], CultureInfo.InvariantCulture,
                DateTimeStyles.AllowInnerWhite, out var time))
        {
            return line;
        }

        var converted = TimeZoneInfo.ConvertTime(DateTime.SpecifyKind(time, DateTimeKind.Unspecified), from, to);
        var replacement = Encoding.ASCII.GetBytes(converted.ToString(CompleteDate, CultureInfo.InvariantCulture));

        return [.. line.AsSpan(0, dateStart), .. replacement, .. line.AsSpan(dateEnd)];
    }

    /// <summary>"Standard" (this machine's zone without daylight saving time), "Local", or a time zone id.</summary>
    public static TimeZoneInfo Zone(string? name) => name switch
    {
        null or "" or "Standard" or "standard" => TimeZoneInfo.CreateCustomTimeZone(
            "Standard", TimeZoneInfo.Local.BaseUtcOffset, TimeZoneInfo.Local.StandardName, TimeZoneInfo.Local.StandardName),
        "Local" or "local" => TimeZoneInfo.Local,
        "UTC" or "utc" => TimeZoneInfo.Utc,
        _ => TimeZoneInfo.FindSystemTimeZoneById(name)
    };
}
