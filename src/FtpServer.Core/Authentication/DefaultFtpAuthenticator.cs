using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using FtpServer.IO;
using FtpServer.Options;
using Microsoft.Extensions.Logging;

namespace FtpServer.Authentication;

/// <summary>
/// Authenticates against the user list in <see cref="FtpAuthenticationOptions"/>, with
/// per-address throttling of failed attempts (RFC 2577 section 3).
/// </summary>
/// <remarks>
/// Reads through <see cref="FtpOptionsProvider"/>, so an account added to the configuration file
/// while the server is running can log in without a restart.
/// </remarks>
public sealed class DefaultFtpAuthenticator(
    FtpOptionsProvider options,
    FtpFileSystemFactory fileSystems,
    ILogger<DefaultFtpAuthenticator> logger
) : IFtpAuthenticator
{
    private readonly ConcurrentDictionary<string, FailureRecord> _failures = new();

    public ValueTask<FtpAuthenticationResult> AuthenticateUserAsync(string userName, EndPoint? remoteEndPoint, CancellationToken token)
    {
        if (IsLockedOut(remoteEndPoint))
        {
            Log.LoginLockedOut(logger, userName, Describe(remoteEndPoint));
            return new ValueTask<FtpAuthenticationResult>(FtpAuthenticationResult.TooManyAttempts);
        }

        // Always ask for a password, so that valid and invalid user names are indistinguishable.
        return new ValueTask<FtpAuthenticationResult>(FtpAuthenticationResult.PasswordRequired);
    }

    public async ValueTask<FtpAuthenticationResult> AuthenticatePasswordAsync(string userName, string password, EndPoint? remoteEndPoint, CancellationToken token)
    {
        var auth = options.Current.Authentication;

        if (IsLockedOut(remoteEndPoint))
        {
            Log.LoginLockedOut(logger, userName, Describe(remoteEndPoint));
            return FtpAuthenticationResult.TooManyAttempts;
        }

        var user = Resolve(userName, password, auth);

        if (user is not null)
        {
            ClearFailures(remoteEndPoint);
            Log.LoginSucceeded(logger, user.Name, Describe(remoteEndPoint));
            return FtpAuthenticationResult.Success(user);
        }

        RecordFailure(remoteEndPoint);
        Log.LoginFailed(logger, userName, Describe(remoteEndPoint));

        if (auth.FailureDelay > TimeSpan.Zero)
        {
            await Task.Delay(auth.FailureDelay, token).ConfigureAwait(false);
        }

        return FtpAuthenticationResult.Failed;
    }

    private FtpUser? Resolve(string userName, string password, FtpAuthenticationOptions auth)
    {
        // A configured account always wins over the anonymous shortcut, so enabling anonymous
        // access cannot silently turn a real user called "ftp" into a passwordless login.
        var isConfigured = false;

        foreach (var candidate in auth.Users)
        {
            if (string.Equals(candidate.Name, userName, StringComparison.Ordinal))
            {
                isConfigured = true;
                break;
            }
        }

        if (!isConfigured && auth.AllowAnonymous &&
            (string.Equals(userName, "anonymous", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(userName, "ftp", StringComparison.OrdinalIgnoreCase)))
        {
            return new FtpUser(userName, isAnonymous: true, isReadOnly: !auth.AnonymousCanWrite, homeDirectory: null);
        }

        foreach (var candidate in auth.Users)
        {
            if (!string.Equals(candidate.Name, userName, StringComparison.Ordinal))
            {
                continue;
            }

            if (!PasswordMatches(candidate, password))
            {
                return null;
            }

            // Only a user with mounts needs a source; without one the session provider takes the
            // plain home-directory path, so an existing configuration behaves exactly as before.
            var fileSystem = candidate.VirtualFolders.Count > 0
                ? fileSystems.SourceFor(candidate)
                : null;

            return new FtpUser(candidate.Name, isAnonymous: false, candidate.ReadOnly, candidate.HomeDirectory, fileSystem);
        }

        return null;
    }

    private static bool PasswordMatches(FtpUserOptions candidate, string password)
    {
        if (!string.IsNullOrEmpty(candidate.PasswordHash))
        {
            return PasswordHash.Verify(candidate.PasswordHash, password);
        }

        if (!string.IsNullOrEmpty(candidate.PasswordSha256))
        {
            Span<byte> actual = stackalloc byte[SHA256.HashSizeInBytes];
            SHA256.HashData(Encoding.UTF8.GetBytes(password), actual);

            return TryDecode(candidate.PasswordSha256, out var expected) &&
                   CryptographicOperations.FixedTimeEquals(actual, expected);
        }

        if (candidate.Password is null)
        {
            return false;
        }

        // Hashing both sides first makes the comparison fixed-width, so the timing cannot reveal
        // the stored password's length the way a direct byte comparison would.
        Span<byte> storedHash = stackalloc byte[SHA256.HashSizeInBytes];
        Span<byte> suppliedHash = stackalloc byte[SHA256.HashSizeInBytes];

        SHA256.HashData(Encoding.UTF8.GetBytes(candidate.Password), storedHash);
        SHA256.HashData(Encoding.UTF8.GetBytes(password), suppliedHash);

        return CryptographicOperations.FixedTimeEquals(suppliedHash, storedHash);
    }

    private static bool TryDecode(string value, out byte[] bytes)
    {
        try
        {
            bytes = value.Length == SHA256.HashSizeInBytes * 2
                ? Convert.FromHexString(value)
                : Convert.FromBase64String(value);

            return bytes.Length == SHA256.HashSizeInBytes;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    private bool IsLockedOut(EndPoint? remoteEndPoint)
    {
        var auth = options.Current.Authentication;

        if (auth.MaxFailedAttempts <= 0 || Key(remoteEndPoint) is not { } key)
        {
            return false;
        }

        if (!_failures.TryGetValue(key, out var record))
        {
            return false;
        }

        if (DateTimeOffset.UtcNow - record.Last > auth.LockoutDuration)
        {
            _failures.TryRemove(key, out _);
            return false;
        }

        return record.Count >= auth.MaxFailedAttempts;
    }

    /// <summary>Entries only expire when the same address reconnects, so the map is swept too.</summary>
    private const int SweepThreshold = 1024;

    private void RecordFailure(EndPoint? remoteEndPoint)
    {
        if (Key(remoteEndPoint) is not { } key)
        {
            return;
        }

        _failures.AddOrUpdate(
            key,
            static _ => new FailureRecord(1, DateTimeOffset.UtcNow),
            static (_, existing) => new FailureRecord(existing.Count + 1, DateTimeOffset.UtcNow));

        // Without this the map grows for the life of the process: one failed login from each of
        // many addresses (a botnet, or any host with a /64) leaves a permanent entry apiece.
        if (_failures.Count > SweepThreshold)
        {
            SweepExpired();
        }
    }

    private void SweepExpired()
    {
        var cutoff = DateTimeOffset.UtcNow - options.Current.Authentication.LockoutDuration;

        foreach (var entry in _failures)
        {
            if (entry.Value.Last < cutoff)
            {
                // Remove only if unchanged, so a concurrent failure is not discarded.
                ((ICollection<KeyValuePair<string, FailureRecord>>)_failures).Remove(entry);
            }
        }
    }

    private void ClearFailures(EndPoint? remoteEndPoint)
    {
        if (Key(remoteEndPoint) is { } key)
        {
            _failures.TryRemove(key, out _);
        }
    }

    private static string? Key(EndPoint? remoteEndPoint) =>
        remoteEndPoint is IPEndPoint ip ? ip.Address.ToString() : null;

    private static string Describe(EndPoint? remoteEndPoint) =>
        Key(remoteEndPoint) ?? "unknown";

    private readonly record struct FailureRecord(int Count, DateTimeOffset Last);
}
