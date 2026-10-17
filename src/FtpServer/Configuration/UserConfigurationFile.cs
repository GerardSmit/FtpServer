using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FtpServer.Configuration;

/// <summary>
/// Reads and edits the <c>Authentication:Users</c> array of a settings file, in place.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a <see cref="JsonNode"/> tree rather than a deserialise/serialise round-trip
/// through <see cref="Options.FtpOptions"/>: the file holds the whole server configuration, and
/// binding it to a model and writing the model back would quietly delete every setting the model
/// does not know about - including settings a newer or older build wrote.
/// </para>
/// <para>
/// <see cref="JsonNode"/> also needs no reflection, so this survives trimming and AOT.
/// </para>
/// </remarks>
public sealed class UserConfigurationFile
{
    private readonly JsonObject _root;

    private UserConfigurationFile(string path, JsonObject root)
    {
        Path = path;
        _root = root;
    }

    public string Path { get; }

    /// <summary>
    /// Loads <paramref name="path"/>, or starts an empty document if the file does not exist yet.
    /// </summary>
    /// <exception cref="JsonException">The file exists but is not a JSON object.</exception>
    public static UserConfigurationFile Load(string path)
    {
        var fullPath = System.IO.Path.GetFullPath(path);

        if (!File.Exists(fullPath))
        {
            return new UserConfigurationFile(fullPath, new JsonObject());
        }

        var text = File.ReadAllText(fullPath);

        // Comments and trailing commas are accepted by the configuration provider, so refusing
        // them here would make a file the server reads happily unmanageable by its own CLI.
        var node = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        });

        if (node is not JsonObject root)
        {
            throw new JsonException($"'{fullPath}' does not contain a JSON object.");
        }

        return new UserConfigurationFile(fullPath, root);
    }

    /// <summary>The user entries, in file order.</summary>
    public IReadOnlyList<JsonObject> Users
    {
        get
        {
            var users = new List<JsonObject>();

            if (_root["Authentication"] is JsonObject authentication &&
                authentication["Users"] is JsonArray array)
            {
                foreach (var entry in array)
                {
                    if (entry is JsonObject user)
                    {
                        users.Add(user);
                    }
                }
            }

            return users;
        }
    }

    public JsonObject? Find(string name)
    {
        foreach (var user in Users)
        {
            if (string.Equals(NameOf(user), name, StringComparison.Ordinal))
            {
                return user;
            }
        }

        return null;
    }

    public static string? NameOf(JsonObject user) => user["Name"]?.GetValue<string>();

    /// <summary>
    /// Appends a user. The caller is expected to have checked <see cref="Find"/> first.
    /// </summary>
    public void Add(string name, string passwordHash, string? homeDirectory, bool readOnly)
    {
        var user = new JsonObject
        {
            ["Name"] = name,
            ["PasswordHash"] = passwordHash,
        };

        if (!string.IsNullOrWhiteSpace(homeDirectory))
        {
            user["HomeDirectory"] = homeDirectory;
        }

        if (readOnly)
        {
            user["ReadOnly"] = true;
        }

        // Cast, so that the JsonNode overload is chosen over the generic one - which serialises an
        // arbitrary value, and is neither trim- nor AOT-safe.
        UsersArray().Add((JsonNode)user);
    }

    /// <summary>
    /// Replaces a user's password, dropping the weaker forms so that a legacy entry cannot keep
    /// authenticating with the password that was just changed.
    /// </summary>
    public bool SetPassword(string name, string passwordHash)
    {
        if (Find(name) is not { } user)
        {
            return false;
        }

        user["PasswordHash"] = passwordHash;
        user.Remove("Password");
        user.Remove("PasswordSha256");

        return true;
    }

    public bool Remove(string name)
    {
        if (_root["Authentication"] is not JsonObject authentication ||
            authentication["Users"] is not JsonArray array)
        {
            return false;
        }

        for (var i = 0; i < array.Count; i++)
        {
            if (array[i] is JsonObject user && string.Equals(NameOf(user), name, StringComparison.Ordinal))
            {
                array.RemoveAt(i);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Writes the document back, replacing the file only once it is complete on disk.
    /// </summary>
    /// <remarks>
    /// Writing in place would leave a truncated configuration behind if the process died
    /// mid-write, and the server reloads this file while it runs.
    /// </remarks>
    public void Save()
    {
        // Relaxed escaping keeps a base64 hash readable, instead of writing its "+" as a +
        // escape in a file an operator still has to edit by hand.
        var json = _root.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
        var directory = System.IO.Path.GetDirectoryName(Path);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // The temporary file has to share the destination's directory, or Move would cross volumes
        // and stop being atomic.
        var temporary = Path + ".tmp";

        File.WriteAllText(temporary, json + Environment.NewLine);

        try
        {
            File.Move(temporary, Path, overwrite: true);
        }
        catch
        {
            TryDelete(temporary);
            throw;
        }
    }

    private JsonArray UsersArray()
    {
        if (_root["Authentication"] is not JsonObject authentication)
        {
            authentication = new JsonObject();
            _root["Authentication"] = authentication;
        }

        if (authentication["Users"] is not JsonArray users)
        {
            users = new JsonArray();
            authentication["Users"] = users;
        }

        return users;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Leaving a stray temporary file behind is not worth masking the real failure.
        }
    }
}
