using System.Net;
using System.Security.Cryptography;
using System.Text;
using FtpServer.IO;
using FtpServer.Options;
using Microsoft.Extensions.Logging;

namespace FtpServer.Authentication;

/// <summary>
/// Authenticates against the user list in <see cref="FtpAuthenticationOptions"/>, with
/// per-address and per-user throttling of failed attempts (RFC 2577 section 3).
/// </summary>
/// <remarks>
/// <para>
/// Reads through <see cref="FtpOptionsProvider"/>, so an account added to the configuration file
/// while the server is running can log in without a restart.
/// </para>
/// <para>
/// An attempt is counted before its password is checked and given back if it succeeds, so
/// connections running in parallel cannot between them exceed the limit while the check is still
/// busy. A success does not clear what the address has failed before: the failures just expire,
/// otherwise a login to an account the attacker owns (or the anonymous one) between guesses would
/// keep the count at zero.
/// </para>
/// </remarks>
public sealed class DefaultFtpAuthenticator(
    FtpOptionsProvider options,
    FtpFileSystemFactory fileSystems,
    ILogger<DefaultFtpAuthenticator> logger
) : IFtpAuthenticator
{
    /// <summary>
    /// Verified against when the user does not exist, so that a wrong name costs as much time as
    /// a wrong password for a real account.
    /// </summary>
    private static readonly string DummyHash = PasswordHash.Create("dummy-password-for-unknown-users");

    private readonly Lock _gate = new();
    private readonly Dictionary<string, FailureRecord> _failures = new();
    private readonly Dictionary<string, FailureRecord> _userFailures = new(StringComparer.OrdinalIgnoreCase);

    public ValueTask<FtpAuthenticationResult> AuthenticateUserAsync(string userName, EndPoint? remoteEndPoint, CancellationToken token)
    {
        if (IsLockedOut(remoteEndPoint))
        {
            Log.LoginLockedOut(logger, FtpLogText.Sanitise(userName), Describe(remoteEndPoint));
            return new ValueTask<FtpAuthenticationResult>(FtpAuthenticationResult.TooManyAttempts);
        }

        // Always ask for a password, so that valid and invalid user names are indistinguishable.
        return new ValueTask<FtpAuthenticationResult>(FtpAuthenticationResult.PasswordRequired);
    }

    public async ValueTask<FtpAuthenticationResult> AuthenticatePasswordAsync(string userName, string password, EndPoint? remoteEndPoint, CancellationToken token)
    {
        var auth = options.Current.Authentication;
        var addressKey = Key(remoteEndPoint);
        var userKey = UserKey(userName);

        // Counted now, before the slow part: a check that is still running must not leave room
        // for another connection to try as well.
        if (!TryReserve(addressKey, userKey, auth))
        {
            Log.LoginLockedOut(logger, FtpLogText.Sanitise(userName), Describe(remoteEndPoint));
            return FtpAuthenticationResult.TooManyAttempts;
        }

        var user = Resolve(userName, password, auth);

        if (user is not null)
        {
            Release(addressKey, userKey);
            Log.LoginSucceeded(logger, FtpLogText.Sanitise(user.Name), Describe(remoteEndPoint));
            return FtpAuthenticationResult.Success(user);
        }

        Log.LoginFailed(logger, FtpLogText.Sanitise(userName), Describe(remoteEndPoint));

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

        // No such account: do the same work a real one would cost, so the time taken does not
        // say whether the name exists.
        PasswordHash.Verify(DummyHash, password);

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

        lock (_gate)
        {
            return IsLockedOut(_failures, key, auth, DateTimeOffset.UtcNow);
        }
    }

    private static bool IsLockedOut(Dictionary<string, FailureRecord> failures, string? key, FtpAuthenticationOptions auth, DateTimeOffset now)
    {
        if (key is null || !failures.TryGetValue(key, out var record))
        {
            return false;
        }

        if (now - record.Last > auth.LockoutDuration)
        {
            failures.Remove(key);
            return false;
        }

        return record.Count >= auth.MaxFailedAttempts;
    }

    /// <summary>Entries only expire when the same key comes back, so the maps are swept too.</summary>
    private const int SweepThreshold = 1024;

    /// <summary>
    /// Most user names tracked at once. Names are chosen by the client, so without a bound a
    /// flood of made-up ones would grow the map for as long as the lockout lasts.
    /// </summary>
    private const int MaxTrackedUsers = 10_000;

    /// <summary>Longest user name kept as a key; a longer one is cut, which only makes it stricter.</summary>
    private const int MaxUserKeyLength = 256;

    /// <summary>
    /// Counts an attempt against the address and the user, unless either is already locked out.
    /// </summary>
    /// <returns><c>false</c> when the attempt is refused outright.</returns>
    private bool TryReserve(string? addressKey, string userKey, FtpAuthenticationOptions auth)
    {
        if (auth.MaxFailedAttempts <= 0)
        {
            return true;
        }

        var now = DateTimeOffset.UtcNow;

        lock (_gate)
        {
            if (IsLockedOut(_failures, addressKey, auth, now) ||
                IsLockedOut(_userFailures, userKey, auth, now))
            {
                return false;
            }

            if (addressKey is not null)
            {
                Count(_failures, addressKey, now);
            }

            if (_userFailures.ContainsKey(userKey) || _userFailures.Count < MaxTrackedUsers)
            {
                Count(_userFailures, userKey, now);
            }

            // Without this the maps grow for the life of the process: one failed login from each
            // of many addresses (a botnet, or any host with a /64) leaves a permanent entry apiece.
            if (_failures.Count > SweepThreshold || _userFailures.Count > SweepThreshold)
            {
                var cutoff = now - auth.LockoutDuration;

                Sweep(_failures, cutoff);
                Sweep(_userFailures, cutoff);
            }

            return true;
        }
    }

    private static void Count(Dictionary<string, FailureRecord> failures, string key, DateTimeOffset now) =>
        failures[key] = failures.TryGetValue(key, out var existing)
            ? new FailureRecord(existing.Count + 1, now)
            : new FailureRecord(1, now);

    /// <summary>
    /// Gives back the attempt of a login that succeeded. Failures from before it stay, and expire
    /// on their own; the user's own count is cleared, as the account has now been proven to be in
    /// the right hands.
    /// </summary>
    private void Release(string? addressKey, string userKey)
    {
        lock (_gate)
        {
            if (addressKey is not null && _failures.TryGetValue(addressKey, out var record))
            {
                if (record.Count <= 1)
                {
                    _failures.Remove(addressKey);
                }
                else
                {
                    _failures[addressKey] = record with { Count = record.Count - 1 };
                }
            }

            _userFailures.Remove(userKey);
        }
    }

    private static void Sweep(Dictionary<string, FailureRecord> failures, DateTimeOffset cutoff)
    {
        foreach (var entry in failures.Where(entry => entry.Value.Last < cutoff).ToList())
        {
            failures.Remove(entry.Key);
        }
    }

    private static string UserKey(string userName) =>
        userName.Length > MaxUserKeyLength ? userName[..MaxUserKeyLength] : userName;

    private static string? Key(EndPoint? remoteEndPoint) =>
        remoteEndPoint is IPEndPoint ip ? ip.Address.ToString() : null;

    private static string Describe(EndPoint? remoteEndPoint) =>
        Key(remoteEndPoint) ?? "unknown";

    private readonly record struct FailureRecord(int Count, DateTimeOffset Last);
}
