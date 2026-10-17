using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Nodes;
using FtpServer.Authentication;

namespace FtpServer.Configuration;

/// <summary>
/// The <c>user</c> and <c>hash</c> verbs, which edit the settings file the server reads.
/// </summary>
public static class UserCommands
{
    public static Command CreateUserCommand(Option<string> configOption)
    {
        var command = new Command("user", "Manage the accounts in the settings file.");

        command.Add(CreateAddCommand(configOption));
        command.Add(CreateListCommand(configOption));
        command.Add(CreateRemoveCommand(configOption));
        command.Add(CreatePasswordCommand(configOption));

        return command;
    }

    public static Command CreateHashCommand()
    {
        var iterations = CreateIterationsOption();

        var command = new Command("hash", "Print a password hash to paste into a settings file.")
        {
            iterations,
        };

        command.SetAction(parseResult =>
        {
            var password = PasswordPrompt.ReadNew();

            if (password is null)
            {
                return 1;
            }

            Console.WriteLine(PasswordHash.Create(password, parseResult.GetValue(iterations)));
            return 0;
        });

        return command;
    }

    private static Command CreateAddCommand(Option<string> configOption)
    {
        var name = new Argument<string>("name") { Description = "Login name." };
        var home = new Option<string?>("--home") { Description = "Home directory, relative to the server root." };
        var readOnly = new Option<bool>("--read-only") { Description = "Refuse every command that would modify the file system." };
        var iterations = CreateIterationsOption();

        var command = new Command("add", "Add a user with a hashed password.")
        {
            name,
            home,
            readOnly,
            iterations,
        };

        command.SetAction(parseResult => Edit(parseResult.GetValue(configOption)!, file =>
        {
            var userName = parseResult.GetValue(name)!;

            if (file.Find(userName) is not null)
            {
                Console.Error.WriteLine($"User '{userName}' already exists. Use 'user passwd' to change the password.");
                return 1;
            }

            var password = PasswordPrompt.ReadNew();

            if (password is null)
            {
                return 1;
            }

            file.Add(
                userName,
                PasswordHash.Create(password, parseResult.GetValue(iterations)),
                parseResult.GetValue(home),
                parseResult.GetValue(readOnly));

            file.Save();

            Console.WriteLine($"Added '{userName}' to {file.Path}.");
            return 0;
        }));

        return command;
    }

    private static Command CreateListCommand(Option<string> configOption)
    {
        var command = new Command("list", "List the configured users.");

        command.SetAction(parseResult => Edit(parseResult.GetValue(configOption)!, file =>
        {
            if (file.Users.Count == 0)
            {
                Console.WriteLine($"No users are configured in {file.Path}.");
                return 0;
            }

            Console.WriteLine($"{"NAME",-20} {"HOME",-24} {"ACCESS",-10} {"FOLDERS",-8} PASSWORD");

            foreach (var user in file.Users)
            {
                Console.WriteLine(string.Format(
                    "{0,-20} {1,-24} {2,-10} {3,-8} {4}",
                    UserConfigurationFile.NameOf(user) ?? "(unnamed)",
                    user["HomeDirectory"]?.GetValue<string>() ?? "(server root)",
                    IsReadOnly(user) ? "read-only" : "read-write",
                    (user["VirtualFolders"] as JsonArray)?.Count ?? 0,
                    DescribePassword(user)));
            }

            return 0;
        }));

        return command;
    }

    private static Command CreateRemoveCommand(Option<string> configOption)
    {
        var name = new Argument<string>("name") { Description = "Login name." };

        var command = new Command("remove", "Remove a user.")
        {
            name,
        };

        command.SetAction(parseResult => Edit(parseResult.GetValue(configOption)!, file =>
        {
            var userName = parseResult.GetValue(name)!;

            if (!file.Remove(userName))
            {
                Console.Error.WriteLine($"No user '{userName}' in {file.Path}.");
                return 1;
            }

            file.Save();

            Console.WriteLine($"Removed '{userName}' from {file.Path}.");
            return 0;
        }));

        return command;
    }

    private static Command CreatePasswordCommand(Option<string> configOption)
    {
        var name = new Argument<string>("name") { Description = "Login name." };
        var iterations = CreateIterationsOption();

        var command = new Command("passwd", "Change a user's password.")
        {
            name,
            iterations,
        };

        command.SetAction(parseResult => Edit(parseResult.GetValue(configOption)!, file =>
        {
            var userName = parseResult.GetValue(name)!;

            if (file.Find(userName) is null)
            {
                Console.Error.WriteLine($"No user '{userName}' in {file.Path}.");
                return 1;
            }

            var password = PasswordPrompt.ReadNew();

            if (password is null)
            {
                return 1;
            }

            file.SetPassword(userName, PasswordHash.Create(password, parseResult.GetValue(iterations)));
            file.Save();

            Console.WriteLine($"Changed the password for '{userName}' in {file.Path}.");
            return 0;
        }));

        return command;
    }

    private static Option<int> CreateIterationsOption() =>
        new("--iterations")
        {
            Description = "PBKDF2 iteration count; higher is slower to verify and slower to attack.",
            DefaultValueFactory = _ => PasswordHash.DefaultIterations,
        };

    /// <summary>
    /// Loads the file, runs <paramref name="action"/>, and turns the failures that are the user's
    /// mistake into a message rather than a stack trace.
    /// </summary>
    private static int Edit(string path, Func<UserConfigurationFile, int> action)
    {
        try
        {
            return action(UserConfigurationFile.Load(path));
        }
        catch (JsonException ex)
        {
            Console.Error.WriteLine($"{path} is not valid JSON: {ex.Message}");
            return 1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Could not update {path}: {ex.Message}");
            return 1;
        }
    }

    private static bool IsReadOnly(JsonObject user) =>
        user["ReadOnly"] is { } value && value.GetValueKind() == JsonValueKind.True;

    private static string DescribePassword(JsonObject user)
    {
        if (user["PasswordHash"] is not null)
        {
            return "PBKDF2";
        }

        if (user["PasswordSha256"] is not null)
        {
            return "SHA-256 (weak)";
        }

        return user["Password"] is not null ? "plain text (weak)" : "none";
    }
}
