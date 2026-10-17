using System.Text;

namespace FtpServer.Configuration;

/// <summary>
/// Reads a password from the console without echoing it.
/// </summary>
/// <remarks>
/// A password is prompted rather than taken as an option on purpose: an argument is recorded in the
/// shell's history file and is visible in the process list to every other user on the machine, for
/// as long as the command runs.
/// </remarks>
public static class PasswordPrompt
{
    /// <summary>
    /// Asks twice and returns the password, or <c>null</c> if the two did not match or the input
    /// was empty.
    /// </summary>
    public static string? ReadNew()
    {
        var password = Read("Password: ");

        if (string.IsNullOrEmpty(password))
        {
            Console.Error.WriteLine("The password must not be empty.");
            return null;
        }

        var confirmation = Read("Confirm password: ");

        if (!string.Equals(password, confirmation, StringComparison.Ordinal))
        {
            Console.Error.WriteLine("The passwords do not match.");
            return null;
        }

        return password;
    }

    public static string Read(string prompt)
    {
        Console.Write(prompt);

        // Redirected input has no key events to read, and no echo to suppress either.
        if (Console.IsInputRedirected)
        {
            var line = Console.ReadLine() ?? string.Empty;
            Console.WriteLine();
            return line;
        }

        var builder = new StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    Console.WriteLine();
                    return builder.ToString();

                case ConsoleKey.Backspace when builder.Length > 0:
                    builder.Length--;
                    break;

                case ConsoleKey.Escape:
                    builder.Clear();
                    Console.WriteLine();
                    return string.Empty;

                default:
                    if (!char.IsControl(key.KeyChar))
                    {
                        builder.Append(key.KeyChar);
                    }

                    break;
            }
        }
    }
}
