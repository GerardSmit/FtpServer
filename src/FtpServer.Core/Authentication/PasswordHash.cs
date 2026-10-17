using System.Security.Cryptography;
using System.Text;

namespace FtpServer.Authentication;

/// <summary>
/// PBKDF2 password hashes, in the form <c>pbkdf2-sha256$iterations$salt$hash</c> with the salt and
/// hash base64-encoded.
/// </summary>
/// <remarks>
/// A password hash has to be slow: against a leaked configuration, a plain digest costs an
/// attacker one hash per guess. The iteration count is what makes a guess expensive.
/// </remarks>
public static class PasswordHash
{
    private const string Prefix = "pbkdf2-sha256";

    /// <summary>Cost of one verification, and so of one guess.</summary>
    public const int DefaultIterations = 210_000;

    private const int SaltLength = 16;
    private const int HashLength = 32;

    public static string Create(string password, int iterations = DefaultIterations)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return $"{Prefix}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Checks <paramref name="password"/> against a stored hash. A malformed hash verifies
    /// nothing rather than everything.
    /// </summary>
    public static bool Verify(string stored, string password)
    {
        var parts = stored.Split('$');

        if (parts.Length != 4 ||
            !string.Equals(parts[0], Prefix, StringComparison.OrdinalIgnoreCase) ||
            !int.TryParse(parts[1], out var iterations) ||
            iterations < 1)
        {
            return false;
        }

        byte[] salt;
        byte[] expected;

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length == 0 || expected.Length == 0)
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
