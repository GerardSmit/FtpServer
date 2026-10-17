using System.Net;
using FtpServer.IO;

namespace FtpServer.Authentication;

/// <summary>
/// Validates the credentials supplied by USER/PASS. Replace the registration in the service
/// collection to plug in a different user store.
/// </summary>
public interface IFtpAuthenticator
{
    /// <summary>
    /// Called on USER. Lets an implementation short-circuit a login that needs no password.
    /// </summary>
    ValueTask<FtpAuthenticationResult> AuthenticateUserAsync(string userName, EndPoint? remoteEndPoint, CancellationToken token);

    /// <summary>
    /// Called on PASS.
    /// </summary>
    ValueTask<FtpAuthenticationResult> AuthenticatePasswordAsync(string userName, string password, EndPoint? remoteEndPoint, CancellationToken token);
}

public enum FtpAuthenticationStatus
{
    /// <summary>Credentials accepted; the session is logged in.</summary>
    Success,

    /// <summary>A password is required for this user (reply 331).</summary>
    PasswordRequired,

    /// <summary>Credentials rejected (reply 530).</summary>
    Failed,

    /// <summary>Too many failed attempts from this address (reply 421 and close).</summary>
    TooManyAttempts,
}

public readonly record struct FtpAuthenticationResult(
    FtpAuthenticationStatus Status,
    FtpUser? User = null)
{
    public static FtpAuthenticationResult PasswordRequired { get; } = new(FtpAuthenticationStatus.PasswordRequired);

    public static FtpAuthenticationResult Failed { get; } = new(FtpAuthenticationStatus.Failed);

    public static FtpAuthenticationResult TooManyAttempts { get; } = new(FtpAuthenticationStatus.TooManyAttempts);

    public static FtpAuthenticationResult Success(FtpUser user) => new(FtpAuthenticationStatus.Success, user);
}

/// <summary>
/// The identity a session is running as, once logged in.
/// </summary>
public sealed class FtpUser(
    string name,
    bool isAnonymous,
    bool isReadOnly,
    string? homeDirectory,
    IFtpFileSystemSource? fileSystem = null)
{
    public string Name { get; } = name;

    public bool IsAnonymous { get; } = isAnonymous;

    public bool IsReadOnly { get; } = isReadOnly;

    /// <summary>
    /// Per-user root, or <c>null</c> to use the server-wide root.
    /// </summary>
    public string? HomeDirectory { get; } = homeDirectory;

    /// <summary>
    /// The tree this user gets, in place of <see cref="HomeDirectory"/>. Lets an authenticator
    /// serve something other than a directory under the configured root - a per-user set of mounts,
    /// an in-memory tree, or a remote store.
    /// </summary>
    /// <remarks>
    /// Takes precedence over <see cref="HomeDirectory"/>, and is not confined to
    /// <see cref="Options.FtpOptions.Path"/>: an authenticator that builds its own file system has
    /// already chosen what the user can reach.
    /// </remarks>
    public IFtpFileSystemSource? FileSystem { get; } = fileSystem;
}
