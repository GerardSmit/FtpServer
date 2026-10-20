namespace FtpServer.Options;

public class FtpOptions
{
    public int Port { get; set; } = 21;

    /// <summary>
    /// Root directory exposed to clients. Every session is confined to this directory.
    /// </summary>
    /// <remarks>
    /// Deliberately not the filesystem root: <see cref="FtpServer.FtpSessionProvider"/> always
    /// mounts this as a sub-filesystem, and a root of "/" would expose the whole host.
    /// </remarks>
    public string Path { get; set; } = "ftproot";

    /// <summary>
    /// Follow junctions, symbolic links and mount points that lead outside <see cref="Path"/>.
    /// </summary>
    /// <remarks>
    /// Off by default: archives, restored backups and other local users all create links the
    /// operator never placed there. Turn it on to treat the root as a mapping rather than a jail.
    /// Hard links are unaffected either way, having no target to refuse to follow.
    /// </remarks>
    public bool FollowLinks { get; set; }

    public bool Ftps { get; set; }

    /// <summary>
    /// Also listen for implicit FTPS on this port (conventionally 990): TLS from the first byte,
    /// before the greeting, with no AUTH command. Null leaves it off. Independent of
    /// <see cref="Ftps"/>, which governs explicit AUTH TLS on <see cref="Port"/>.
    /// </summary>
    public int? ImplicitTlsPort { get; set; }

    /// <summary>
    /// Require the client to issue AUTH TLS before USER/PASS.
    /// </summary>
    public bool RequireTls { get; set; }

    /// <summary>
    /// Offer passive data connections. On by default: RFC 1123 sections 4.1.2.6 and 4.1.2.13 put
    /// PASV in the minimum implementation, and a client behind NAT can use nothing else.
    /// </summary>
    public bool Passive { get; set; } = true;

    /// <summary>
    /// Reject every command that would modify the file system.
    /// </summary>
    public bool ReadOnly { get; set; }

    /// <summary>
    /// Directories grafted onto every session's tree, whoever is logged in.
    /// </summary>
    /// <remarks>
    /// A user's own <see cref="FtpUserOptions.VirtualFolders"/> is added to these, and an entry
    /// there mounting the same path takes the place of the one here.
    /// </remarks>
    public IList<FtpVirtualFolderOptions> VirtualFolders { get; set; } = new List<FtpVirtualFolderOptions>();

    public FtpAuthenticationOptions Authentication { get; set; } = new();

    public FtpConnectionOptions Connection { get; set; } = new();

    public FtpDataConnectionOptions DataConnection { get; set; } = new();

    public FtpCertificateOptions Certificate { get; set; } = new();

    public FtpFeatureOptions Features { get; set; } = new();

    public PassivePortRangeOptions PassivePortRange { get; set; } = new();

    public FtpListOptions List { get; set; } = new();
}

public class FtpAuthenticationOptions
{
    /// <summary>
    /// Allow the well-known "anonymous"/"ftp" user with any password.
    /// </summary>
    public bool AllowAnonymous { get; set; }

    /// <summary>
    /// Grant anonymous sessions write access. Ignored unless <see cref="AllowAnonymous"/> is set.
    /// </summary>
    public bool AnonymousCanWrite { get; set; }

    public IList<FtpUserOptions> Users { get; set; } = new List<FtpUserOptions>();

    /// <summary>
    /// Failed logins from one address before it is refused. Zero disables the limit.
    /// </summary>
    public int MaxFailedAttempts { get; set; } = 5;

    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Artificial delay applied to a failed PASS, to slow down password guessing (RFC 2577).
    /// </summary>
    public TimeSpan FailureDelay { get; set; } = TimeSpan.FromSeconds(1);
}

public class FtpUserOptions
{
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Plain-text password. Ignored when <see cref="PasswordSha256"/> is set.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Base64 or hex encoded SHA-256 of the password.
    /// </summary>
    /// <remarks>
    /// Unsalted and fast, so a leaked configuration can be cracked offline. Kept for existing
    /// configurations; <see cref="PasswordHash"/> is what a new one should use.
    /// </remarks>
    public string? PasswordSha256 { get; set; }

    /// <summary>
    /// PBKDF2 password hash, in the form <c>pbkdf2-sha256$iterations$salt$hash</c> with the salt
    /// and hash base64-encoded. Preferred over <see cref="Password"/> and
    /// <see cref="PasswordSha256"/>, because the iteration count gives each guess a cost.
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// Optional per-user root, relative to <see cref="FtpOptions.Path"/> or absolute.
    /// </summary>
    public string? HomeDirectory { get; set; }

    public bool ReadOnly { get; set; }

    /// <summary>
    /// Directories grafted onto this user's tree at a path of the operator's choosing.
    /// </summary>
    public IList<FtpVirtualFolderOptions> VirtualFolders { get; set; } = new List<FtpVirtualFolderOptions>();
}

/// <summary>
/// A directory mounted into a user's tree, from anywhere on the host.
/// </summary>
public class FtpVirtualFolderOptions
{
    /// <summary>
    /// Where the folder appears in the user's tree, for example <c>/shared</c>.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// The directory it maps to: absolute, or relative to <see cref="FtpOptions.Path"/>.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="FtpUserOptions.HomeDirectory"/> this is not confined to the server root -
    /// mapping a directory from elsewhere on the host is the point. Only the mapped subtree is
    /// reachable through the mount.
    /// </remarks>
    public string PhysicalPath { get; set; } = string.Empty;

    /// <summary>
    /// Serve this folder read-only, whatever the user's own access is.
    /// </summary>
    public bool ReadOnly { get; set; }

    /// <summary>
    /// Overrides <see cref="FtpOptions.FollowLinks"/> for this mount alone.
    /// </summary>
    public bool? FollowLinks { get; set; }
}

public class FtpConnectionOptions
{
    /// <summary>
    /// Simultaneous control connections. Zero disables the limit.
    /// </summary>
    public int MaxConnections { get; set; } = 100;

    /// <summary>
    /// Simultaneous control connections from a single address. Zero disables the limit.
    /// </summary>
    public int MaxConnectionsPerAddress { get; set; } = 10;

    /// <summary>
    /// Longest accepted command line. Longer lines are answered 500 and the session is closed.
    /// </summary>
    public int MaxCommandLength { get; set; } = 4096;

    /// <summary>
    /// Idle time before the control connection is closed with 421.
    /// </summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Time a client has to log in, counted from the connection being accepted. A session that is
    /// not logged in by then is answered 421 and closed. Commands sent before the login do not
    /// extend it, so NOOP cannot be used to hold a connection slot.
    /// </summary>
    public TimeSpan LoginTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Longest a reply on the control connection may take to be handed to the network. A client
    /// that pipelines commands and stops reading would otherwise block the session forever; when
    /// the deadline passes the connection is aborted.
    /// </summary>
    public TimeSpan WriteTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Time allowed for a TLS handshake on the control or data connection.
    /// </summary>
    public TimeSpan TlsHandshakeTimeout { get; set; } = TimeSpan.FromSeconds(15);
}

public class FtpDataConnectionOptions
{
    /// <summary>
    /// Allow PORT/EPRT to name a host other than the control connection's peer.
    /// Leaving this off is what prevents the FTP bounce attack (RFC 2577 section 2).
    /// </summary>
    public bool AllowForeignHost { get; set; }

    /// <summary>
    /// Reject PORT/EPRT targets below this port. Guards against bouncing into system services.
    /// </summary>
    public int MinimumPort { get; set; } = 1024;

    /// <summary>
    /// Require a passive data connection to originate from the control connection's peer.
    /// </summary>
    public bool VerifyPeerAddress { get; set; } = true;

    /// <summary>
    /// IP address advertised in PASV/LPSV replies when the server sits behind NAT or in a container,
    /// in place of a local address the client cannot reach. Used for every peer but a loopback one,
    /// LAN peers included, so it must be an address those reach too; EPSV never carries an address
    /// and is unaffected.
    /// </summary>
    public string? PublicAddress { get; set; }

    /// <summary>
    /// How long a passive port stays reserved waiting for the client to connect.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Timeout applied when connecting out in active mode.
    /// </summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Longest a transfer may go without moving a single byte before it is abandoned.
    /// </summary>
    /// <remarks>
    /// The control connection's idle timer is suspended during a transfer, so without this a
    /// client that opens a data connection and stalls holds its session slot indefinitely.
    /// </remarks>
    public TimeSpan InactivityTimeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Largest file, in bytes, a client may upload; null (the default) means unlimited.
    /// </summary>
    /// <remarks>
    /// Counted on the bytes written to the file, that is after MODE Z decompression, so a small
    /// compressed stream cannot expand past it. It limits the size the file ends up with, so an
    /// APPE or an upload resumed with REST only gets the room that is left. An upload that would
    /// go past it is answered 552 and treated as aborted: what was written so far stays, as with
    /// any other interrupted upload.
    /// </remarks>
    public long? MaxUploadSize { get; set; }
}

public class FtpCertificateOptions
{
    /// <summary>
    /// Path to a PFX/PKCS#12 file. When unset a self-signed certificate is generated.
    /// </summary>
    public string? Path { get; set; }

    public string? Password { get; set; }

    /// <summary>
    /// Subject used for the generated self-signed certificate.
    /// </summary>
    public string SelfSignedSubject { get; set; } = "localhost";

    /// <summary>
    /// Lowest TLS version accepted. Empty means "let the OS decide", which is the recommended default.
    /// </summary>
    public string? MinimumProtocol { get; set; }

    /// <summary>
    /// Allow a TLS session to be resumed on a later connection.
    /// </summary>
    /// <remarks>
    /// Keep this on: FileZilla and others can be configured to require that the data connection
    /// resumes the control connection's session, and refuse every transfer without it.
    /// </remarks>
    public bool AllowTlsResume { get; set; } = true;
}

public class FtpFeatureOptions
{
    public bool XCRC { get; set; } = true;

    /// <summary>
    /// Honour "LIST -R". When off the flag is ignored and only the named directory is listed,
    /// which caps what one command can make the server walk.
    /// </summary>
    public bool LISTR { get; set; } = true;

    public bool MLST { get; set; } = true;

    public bool Hash { get; set; } = true;

    /// <summary>
    /// Advertise and honour SITE sub-commands (CHMOD, UTIME, HELP).
    /// </summary>
    public bool Site { get; set; } = true;

    /// <summary>
    /// On a host without Unix mode bits (Windows), answer SITE CHMOD with 200 and change nothing,
    /// rather than 504.
    /// </summary>
    /// <remarks>
    /// On by default because clients that copy permissions on upload - Beyond Compare does unless
    /// told otherwise - send CHMOD after every STOR and report each refusal as a failed transfer.
    /// The 200 says plainly that the mode was ignored.
    /// </remarks>
    public bool IgnoreUnsupportedChmod { get; set; } = true;

    /// <summary>
    /// Offer MODE Z: deflate compression of the data connection (draft-preston-ftpext-deflate),
    /// which clients only use when FEAT lists it and their user asks for it.
    /// </summary>
    public bool ModeZ { get; set; } = true;

    /// <summary>
    /// Honour SITE SYMLINK. Off by default: a link is a lasting change to what the tree exposes.
    /// Links are confined to the session's own tree either way - a target that resolves outside
    /// it is refused - but an operator should still opt in to letting users create them.
    /// </summary>
    public bool SiteSymlink { get; set; }
}

public class PassivePortRangeOptions
{
    public int Start { get; set; } = 50000;

    public int End { get; set; } = 50100;
}

public class FtpListOptions
{
    /// <summary>
    /// Limit of the recursion depth for the "LIST -R" command.
    /// </summary>
    public int RecursionLimit { get; set; } = 10;

    /// <summary>
    /// Total entries a single LIST may emit. Bounds memory for a deep or wide tree.
    /// </summary>
    public int MaxEntries { get; set; } = 100_000;

    /// <summary>
    /// The id of the time zone LIST times are written in, such as "UTC" or "Europe/Amsterdam";
    /// empty is this machine's. MLSx and MDTM are always UTC. A client that converts LIST times
    /// needs to know the zone, which a fixed one such as UTC tells it regardless of where the
    /// server runs.
    /// </summary>
    public string? TimeZone { get; set; }

    // One reference, so a listing on another thread never sees half of it.
    private ResolvedZone? _resolved;

    /// <summary>The zone <see cref="TimeZone"/> names; this machine's when it is empty.</summary>
    public TimeZoneInfo ResolveTimeZone()
    {
        if (_resolved is { } resolved && resolved.Id == TimeZone)
        {
            return resolved.Zone;
        }

        var zone = TryFindTimeZone(TimeZone, out var found) ? found : TimeZoneInfo.Local;
        _resolved = new ResolvedZone(TimeZone, zone);
        return zone;
    }

    internal static bool TryFindTimeZone(string? id, out TimeZoneInfo zone)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            zone = TimeZoneInfo.Local;
            return true;
        }

        // UTC needs no time zone data, which a slim container image may not have.
        if (string.Equals(id, "UTC", StringComparison.OrdinalIgnoreCase))
        {
            zone = TimeZoneInfo.Utc;
            return true;
        }

        if (TimeZoneInfo.TryFindSystemTimeZoneById(id, out var found))
        {
            zone = found;
            return true;
        }

        zone = TimeZoneInfo.Local;
        return false;
    }

    private sealed record ResolvedZone(string? Id, TimeZoneInfo Zone);
}
