using System.Net;

namespace FtpServer.Options;

/// <summary>
/// Rejects a configuration that would otherwise fail confusingly at runtime.
/// </summary>
/// <remarks>
/// A plain static check rather than an <c>IValidateOptions</c>: the same rules have to run twice,
/// once at startup where a failure must stop the server, and once per reload where a failure must
/// be reported and the previous configuration kept. See <see cref="FtpOptionsProvider"/>.
/// </remarks>
public static class FtpOptionsValidator
{
    public static bool Validate(FtpOptions options, out string? error)
    {
        if (options.Port is < 1 or > 65535)
        {
            error = "Port must be between 1 and 65535.";
            return false;
        }

        var range = options.PassivePortRange;

        if (range.Start is < 1 or > 65535 || range.End is < 1 or > 65535 || range.End < range.Start)
        {
            error = "PassivePortRange must be a valid, non-empty port range.";
            return false;
        }

        // A passive range covering the control port means a passive bind can steal the listener's
        // port after a restart.
        if (options.Port >= range.Start && options.Port <= range.End)
        {
            error = "PassivePortRange must not contain the control port.";
            return false;
        }

        // The lower bound keeps the longest legal command working; the upper bound stops the
        // "line too long" guard being configured away.
        if (options.Connection.MaxCommandLength is < 64 or > 1024 * 1024)
        {
            error = "Connection.MaxCommandLength must be between 64 and 1048576.";
            return false;
        }

        // Zero would not mean "off": a deadline that has already passed refuses everything, and
        // an inactivity limit of zero abandons every transfer at its first read.
        if (options.Connection.IdleTimeout <= TimeSpan.Zero ||
            options.Connection.LoginTimeout <= TimeSpan.Zero ||
            options.Connection.WriteTimeout <= TimeSpan.Zero ||
            options.Connection.TlsHandshakeTimeout <= TimeSpan.Zero ||
            options.DataConnection.Timeout <= TimeSpan.Zero ||
            options.DataConnection.InactivityTimeout <= TimeSpan.Zero ||
            options.DataConnection.ConnectTimeout <= TimeSpan.Zero)
        {
            error = "Timeouts must be greater than zero.";
            return false;
        }

        if (options.DataConnection.MaxUploadSize is < 0)
        {
            error = "DataConnection.MaxUploadSize must not be negative.";
            return false;
        }

        if (options.Authentication.LockoutDuration < TimeSpan.Zero ||
            options.Authentication.FailureDelay < TimeSpan.Zero)
        {
            error = "Authentication.LockoutDuration and Authentication.FailureDelay must not be negative.";
            return false;
        }

        if (options.List.RecursionLimit < 0 || options.List.MaxEntries < 1)
        {
            error = "List.RecursionLimit must not be negative and List.MaxEntries must be at least 1.";
            return false;
        }

        if (!FtpListOptions.TryFindTimeZone(options.List.TimeZone, out _))
        {
            error = $"List.TimeZone '{options.List.TimeZone}' is not a time zone on this machine.";
            return false;
        }

        if (options.DataConnection.MinimumPort is < 0 or > 65535)
        {
            error = "DataConnection.MinimumPort must be between 0 and 65535.";
            return false;
        }

        // A PublicAddress that does not parse would be silently ignored per PASV, leaving NAT
        // clients with the private address the operator tried to fix.
        if (options.DataConnection.PublicAddress is { Length: > 0 } publicAddress &&
            !IPAddress.TryParse(publicAddress, out _))
        {
            error = "DataConnection.PublicAddress is not an IP address.";
            return false;
        }

        // FTPS with a certificate file that is not there would otherwise fail once per client
        // instead of once at startup.
        if (options.ImplicitTlsPort is { } implicitPort &&
            (implicitPort is < 1 or > 65535 || implicitPort == options.Port))
        {
            error = "ImplicitTlsPort must be between 1 and 65535 and differ from Port.";
            return false;
        }

        if ((options.Ftps || options.ImplicitTlsPort is not null) &&
            options.Certificate.Path is { Length: > 0 } certificatePath &&
            !File.Exists(certificatePath))
        {
            error = $"Certificate.Path '{certificatePath}' does not exist.";
            return false;
        }

        // An unrecognised value is indistinguishable from "let the OS decide", so a typo in a
        // request for TLS 1.3 would quietly leave TLS 1.2 enabled.
        if (!CertificateProvider.TryParseProtocols(options.Certificate.MinimumProtocol, out _))
        {
            error = "Certificate.MinimumProtocol is not a recognised TLS version.";
            return false;
        }

        // RequireTls without Ftps is unsatisfiable: USER is refused until AUTH TLS, and AUTH TLS
        // is refused because TLS is off, so no client can ever log in.
        if (options is { RequireTls: true, Ftps: false })
        {
            error = "RequireTls needs Ftps to be enabled.";
            return false;
        }

        // A filesystem root would serve the whole host. The session provider jails it either way,
        // but nothing can narrow a per-user home below a drive root.
        if (IsFilesystemRoot(options.Path))
        {
            error = "Path must not be a filesystem root.";
            return false;
        }

        if (!ValidateFolders(options.VirtualFolders, "the server", out error))
        {
            return false;
        }

        foreach (var user in options.Authentication.Users)
        {
            if (!ValidateUser(user, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool ValidateUser(FtpUserOptions user, out string? error)
    {
        if (string.IsNullOrWhiteSpace(user.Name))
        {
            error = "Every configured user needs a name.";
            return false;
        }

        if (user.Password is null &&
            string.IsNullOrEmpty(user.PasswordSha256) &&
            string.IsNullOrEmpty(user.PasswordHash))
        {
            error = $"User '{user.Name}' has no password configured.";
            return false;
        }

        return ValidateFolders(user.VirtualFolders, $"user '{user.Name}'", out error);
    }

    /// <summary>
    /// Checks one list of mounts. <paramref name="owner"/> names whose list it is, for the message.
    /// </summary>
    private static bool ValidateFolders(IList<FtpVirtualFolderOptions> folders, string owner, out string? error)
    {
        for (var i = 0; i < folders.Count; i++)
        {
            var folder = folders[i];

            if (!IsValidVirtualPath(folder.Path))
            {
                error = $"A virtual folder of {owner} has an invalid path '{folder.Path}'. " +
                        "It must be absolute, must not be the root, and must not contain '..'.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(folder.PhysicalPath) || IsFilesystemRoot(folder.PhysicalPath))
            {
                error = $"Virtual folder '{folder.Path}' of {owner} needs a PhysicalPath that is not a filesystem root.";
                return false;
            }

            // Two mounts on the same path would be a silent contest, and Zio refuses the second at
            // mount time - after the session has already been handed a half-built tree. A user
            // repeating a server-wide path is not this: that one replaces rather than collides.
            for (var j = 0; j < i; j++)
            {
                if (string.Equals(Normalise(folders[j].Path), Normalise(folder.Path), StringComparison.Ordinal))
                {
                    error = $"{owner} mounts '{folder.Path}' twice.";
                    return false;
                }
            }
        }

        error = null;
        return true;
    }

    /// <summary>
    /// A mount path must be absolute and name something, so that it can be reached from the login
    /// directory and cannot displace the root itself.
    /// </summary>
    internal static bool IsValidVirtualPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalised = Normalise(path);

        if (normalised.Length <= 1)
        {
            return false;
        }

        foreach (var segment in normalised.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment is "." or "..")
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Accepts "shared", "/shared" and "\shared\" alike, as an operator writes all three.</summary>
    internal static string Normalise(string path)
    {
        var trimmed = path.Replace('\\', '/').TrimEnd('/');

        return trimmed.StartsWith('/') ? trimmed : "/" + trimmed;
    }

    internal static bool IsFilesystemRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var full = Path.GetFullPath(path);
            return Path.GetPathRoot(full) is { } root &&
                   string.Equals(Path.TrimEndingDirectorySeparator(full), Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            // An unusable path is invalid for a different reason, reported elsewhere.
            return false;
        }
    }
}
