namespace FtpServer;

/// <summary>
/// Makes text that came from a client safe to write to a log line.
/// </summary>
internal static class FtpLogText
{
    /// <summary>Longest client-supplied value kept in a log entry.</summary>
    public const int MaxLength = 64;

    /// <summary>
    /// Replaces control characters (CR and LF among them, which would start a forged log line) and
    /// cuts the text to <see cref="MaxLength"/> characters.
    /// </summary>
    public static string Sanitise(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var length = Math.Min(value.Length, MaxLength);

        return string.Create(length, value, static (span, source) =>
        {
            for (var i = 0; i < span.Length; i++)
            {
                span[i] = char.IsControl(source[i]) ? '?' : source[i];
            }
        });
    }
}
