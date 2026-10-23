namespace FtpServer.Handlers;

/// <summary>
/// A SITE sub-command added by the host: register it in the service collection. SITE HELP and the
/// FEAT SITE line list it, and it only runs for a session that is logged in.
/// </summary>
public interface IFtpSiteCommand
{
    /// <summary>The word after SITE, matched without regard to case.</summary>
    string Name { get; }

    /// <summary>
    /// Whether the command is on offer to <paramref name="session"/> right now: when not, SITE HELP and FEAT leave it
    /// out and it is refused as unknown, for a command the host switches on and off while running.
    /// </summary>
    bool IsAvailable(FtpSession session) => true;

    /// <summary>Answers the command; <paramref name="argument"/> is the text after the name, trimmed.</summary>
    ValueTask ExecuteAsync(FtpSession session, string argument, CancellationToken token);
}
