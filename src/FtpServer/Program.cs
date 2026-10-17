using System.CommandLine;
using FtpServer;
using FtpServer.Configuration;

var configOption = new Option<string>("--config")
{
    Description = "Settings file to read, and for the management commands, to write.",
    Recursive = true,
    DefaultValueFactory = _ => ServerRunner.DefaultConfigPath,
};

var root = new RootCommand("FTP server. Run without a command to start serving.")
{
    configOption,
};

// Unmatched tokens are how "--Port 2121" and every other setting still reaches the configuration
// when the server is started with no verb.
root.TreatUnmatchedTokensAsErrors = false;

root.SetAction((parseResult, token) =>
    ServerRunner.RunAsync(parseResult.GetValue(configOption)!, parseResult.UnmatchedTokens, token));

root.Add(UserCommands.CreateUserCommand(configOption));
root.Add(UserCommands.CreateHashCommand());

return await root.Parse(args).InvokeAsync();
