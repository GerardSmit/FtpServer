using System.Text.Json;
using System.Text.Json.Nodes;
using FtpServer.Authentication;
using FtpServer.Configuration;

namespace FtpServer.Tests;

/// <summary>
/// The settings file editing behind "FtpServer user add" and friends.
/// </summary>
public class UserConfigurationFileTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "ftpcfg-" + Guid.NewGuid().ToString("N")[..8]);

    private string Write(string json)
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "appsettings.json");
        File.WriteAllText(path, json);
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // Temporary directory; the OS will get to it.
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Adding_a_user_leaves_every_other_setting_alone()
    {
        var path = Write("""
            {
              "Port": 2121,
              "Path": "ftproot",
              "Certificate": { "SelfSignedSubject": "example.com" },
              "Authentication": { "AllowAnonymous": true, "Users": [] }
            }
            """);

        var file = UserConfigurationFile.Load(path);
        file.Add("alice", PasswordHash.Create("secret", iterations: 1000), "alice", readOnly: false);
        file.Save();

        var root = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;

        Assert.Equal(2121, root["Port"]!.GetValue<int>());
        Assert.Equal("example.com", root["Certificate"]!["SelfSignedSubject"]!.GetValue<string>());
        Assert.True(root["Authentication"]!["AllowAnonymous"]!.GetValue<bool>());

        var user = Assert.Single(UserConfigurationFile.Load(path).Users);

        Assert.Equal("alice", UserConfigurationFile.NameOf(user));
        Assert.Equal("alice", user["HomeDirectory"]!.GetValue<string>());
        Assert.Null(user["ReadOnly"]);
        Assert.True(PasswordHash.Verify(user["PasswordHash"]!.GetValue<string>(), "secret"));
    }

    [Fact]
    public void An_added_user_is_a_valid_login_for_the_authenticator()
    {
        var path = Write("{}");

        var file = UserConfigurationFile.Load(path);
        file.Add("bob", PasswordHash.Create("hunter2", iterations: 1000), homeDirectory: null, readOnly: true);
        file.Save();

        var stored = Assert.Single(UserConfigurationFile.Load(path).Users);

        Assert.True(stored["ReadOnly"]!.GetValue<bool>());
        Assert.True(PasswordHash.Verify(stored["PasswordHash"]!.GetValue<string>(), "hunter2"));
        Assert.False(PasswordHash.Verify(stored["PasswordHash"]!.GetValue<string>(), "hunter3"));
    }

    [Fact]
    public void Unknown_properties_on_a_user_survive_an_edit()
    {
        var path = Write("""
            {
              "Authentication": {
                "Users": [
                  { "Name": "alice", "Password": "plain", "VirtualFolders": [ { "Path": "/shared", "PhysicalPath": "D:/shared" } ] }
                ]
              }
            }
            """);

        var file = UserConfigurationFile.Load(path);

        Assert.True(file.SetPassword("alice", PasswordHash.Create("new", iterations: 1000)));
        file.Save();

        var user = Assert.Single(UserConfigurationFile.Load(path).Users);

        // The weaker forms go, so the old password stops working; everything else stays.
        Assert.Null(user["Password"]);
        Assert.Equal("/shared", user["VirtualFolders"]![0]!["Path"]!.GetValue<string>());
        Assert.True(PasswordHash.Verify(user["PasswordHash"]!.GetValue<string>(), "new"));
    }

    [Fact]
    public void Removing_reports_whether_the_user_was_there()
    {
        var path = Write("""
            { "Authentication": { "Users": [ { "Name": "alice", "Password": "x" } ] } }
            """);

        var file = UserConfigurationFile.Load(path);

        Assert.False(file.Remove("nobody"));
        Assert.True(file.Remove("alice"));

        file.Save();

        Assert.Empty(UserConfigurationFile.Load(path).Users);
    }

    [Fact]
    public void A_file_with_comments_is_still_manageable()
    {
        // The configuration provider accepts these, so refusing them would make a file the server
        // reads happily unmanageable by its own CLI.
        var path = Write("""
            {
              // the port clients connect to
              "Port": 2121,
              "Authentication": { "Users": [] },
            }
            """);

        var file = UserConfigurationFile.Load(path);
        file.Add("alice", PasswordHash.Create("secret", iterations: 1000), null, readOnly: false);
        file.Save();

        Assert.Single(UserConfigurationFile.Load(path).Users);
    }

    [Fact]
    public void A_file_that_is_not_json_is_reported_rather_than_overwritten()
    {
        var path = Write("this is not json");

        Assert.ThrowsAny<JsonException>(() => UserConfigurationFile.Load(path));
        Assert.Equal("this is not json", File.ReadAllText(path));
    }

    [Fact]
    public void A_missing_file_is_created_on_save()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "new.json");

        var file = UserConfigurationFile.Load(path);
        file.Add("alice", PasswordHash.Create("secret", iterations: 1000), null, readOnly: false);
        file.Save();

        Assert.True(File.Exists(path));
        Assert.Single(UserConfigurationFile.Load(path).Users);
        Assert.False(File.Exists(path + ".tmp"));
    }
}
