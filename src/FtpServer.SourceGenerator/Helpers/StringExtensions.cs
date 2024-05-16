using System;

namespace FtpServer.SourceGenerator.Helpers;

public static class StringExtensions
{
    private static readonly string[] NewLines = { "\r\n", "\r", "\n" };

    /// <summary>Splits the specified <paramref name="value"/> based on line ending.</summary>
    /// <param name="value">The input string to split.</param>
    /// <returns>An array of each line in the string.</returns>
    public static string[] GetLines(this string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }

        return value.Split(NewLines, StringSplitOptions.None);
    }

    /// <summary>Verifies if the string contains a new line.</summary>
    /// <param name="value">The input string to check.</param>
    /// <returns>True if the string contains a new line, false otherwise.</returns>
    public static bool HasNewLine(this string value)
    {
        return value.AsSpan().IndexOfAny(['\r', '\n']) != -1;
    }

    public static string ToCamelCase(this string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        return char.ToLowerInvariant(value[0]) + value[1..];
    }
}
