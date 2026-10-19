using System.Buffers;
using System.Net;
using System.Net.Sockets;
using FtpServer.Extensions;
using FtpServer.IO;
using Zio;

namespace FtpServer.Handlers;

public partial class DefaultFtpCommandHandler
{
    public override ValueTask SystemTypeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("215 UNIX Type: L8\r\n"u8, token);

    public override ValueTask NoOperationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("200 Command okay.\r\n"u8, token);

    public override ValueTask ClientNameAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        // Purely informational; acknowledging it keeps Total Commander and lftp quiet.
        => session.WriteAsync("200 Command okay.\r\n"u8, token);

    // ---- FEAT -------------------------------------------------------------

    public override ValueTask FeatureListAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        var features = options.Current.Features;

        // RFC 2389 section 3.2: one feature per line, each preceded by a single space.
        var lines = new List<string> { "Features:" };

        if (options.Current.Ftps && !session.IsImplicitTls)
        {
            // RFC 4217 section 6 requires all three to be advertised.
            lines.Add(" AUTH TLS");
            lines.Add(" PBSZ");
            lines.Add(" PROT");
        }
        else if (session.IsImplicitTls)
        {
            // Already protected, so there is nothing for AUTH to do; the data channel is still
            // negotiable.
            lines.Add(" PBSZ");
            lines.Add(" PROT");
        }

        lines.Add(" EPRT");

        // EPSV and PASV only work when passive mode is enabled; advertising them otherwise sends
        // clients down a path that answers 502.
        if (options.Current.Passive)
        {
            lines.Add(" EPSV");
            lines.Add(" PASV");
        }

        // RFC 7151 section 3.1: a server that supports HOST must advertise it.
        lines.Add(" HOST");
        lines.Add(" LANG EN*");

        if (features.MLST)
        {
            // The asterisk marks a fact as enabled (RFC 3659 section 7.8).
            lines.Add(" MLST " + MlsxFactList(session.EnabledFacts));
            lines.Add(" MLSD");
        }

        lines.Add(" MDTM");
        lines.Add(" MFMT");

        if (CanSetCreationTime)
        {
            lines.Add(" MFCT");
        }

        lines.Add(" MFF " + ModifiableFacts(session));

        if (features.ModeZ)
        {
            lines.Add(" MODE Z");
        }

        lines.Add(" REST STREAM");
        lines.Add(" SIZE");
        lines.Add(" TVFS");
        lines.Add(" UTF8");

        lines.Add(" AVBL");
        lines.Add(" CSID");
        lines.Add(" DSIZ");
        lines.Add(" RMDA");

        if (features.Hash)
        {
            lines.Add(" HASH " + HashAlgorithms.FeatureLine(session.HashAlgorithm));

            // Deliberately not " RANG STREAM": draft-bryan-ftp-range section 3.1 makes that
            // string a commitment that RETR and STOR honour octet ranges. They do not, and a
            // client that believed otherwise would send only a partial payload to a STOR that
            // truncates. RANG here applies to HASH alone.
        }

        if (features.XCRC)
        {
            lines.Add(" XCRC");
            lines.Add(" XMD5");
            lines.Add(" XSHA1");
            lines.Add(" XSHA256");
            lines.Add(" XSHA512");
        }

        if (features.Site)
        {
            lines.Add(" SITE " + string.Join(';', SiteCommands()));
        }

        return session.WriteMultilineAsync("211", lines, "End", token);
    }

    // ---- OPTS -------------------------------------------------------------

    public override ValueTask SelectFeatureOptionsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (data.IsEmpty)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        var text = data.GetString(session.Encoding).Trim();
        var space = text.IndexOf(' ');
        var name = (space < 0 ? text : text[..space]).ToUpperInvariant();
        var argument = space < 0 ? string.Empty : text[(space + 1)..].Trim();

        switch (name)
        {
            case "UTF8" or "UTF-8":
                // RFC 2640; clients send both "OPTS UTF8 ON" and a bare "OPTS UTF8".
                if (argument.Length == 0 || argument.Equals("ON", StringComparison.OrdinalIgnoreCase))
                {
                    // The strict decoder, not a fresh UTF8Encoding: that one turns invalid bytes into
                    // U+FFFD, which aliases distinct byte strings onto one pathname.
                    session.Encoding = FtpSession.DefaultEncoding;
                    return session.WriteAsync("200 UTF8 set to on.\r\n"u8, token);
                }

                if (argument.Equals("OFF", StringComparison.OrdinalIgnoreCase))
                {
                    session.Encoding = System.Text.Encoding.ASCII;
                    return session.WriteAsync("200 UTF8 set to off.\r\n"u8, token);
                }

                return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);

            case "MLST":
                {
                    // RFC 3659 section 7.9: the requested facts become the ones the server emits, and
                    // the reply states the set that actually took effect.
                    if (!TryParseFactList(argument, out var facts))
                    {
                        // The fact set is left unchanged on a malformed list, per the §7.9.2 example.
                        return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
                    }

                    session.EnabledFacts = facts;

                    // The space belongs inside the optional group of "MLST OPTS" [ SP factlist ], so
                    // an empty selection replies with no trailing space.
                    var selected = MlsxFactList(facts, marked: false);
                    return session.WriteAsync(selected.Length == 0 ? "200 MLST OPTS\r\n" : $"200 MLST OPTS {selected}\r\n", token);
                }

            case "MODE":
                {
                    // draft-preston-ftpext-deflate: "OPTS MODE Z LEVEL <n>", n from 0 to 9.
                    var parts = argument.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    if (!options.Current.Features.ModeZ ||
                        parts.Length == 0 ||
                        !parts[0].Equals("Z", StringComparison.OrdinalIgnoreCase))
                    {
                        return session.WriteAsync("501 Option not understood.\r\n"u8, token);
                    }

                    if (parts.Length != 3 ||
                        !parts[1].Equals("LEVEL", StringComparison.OrdinalIgnoreCase) ||
                        !int.TryParse(parts[2], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var level) ||
                        level > 9)
                    {
                        return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
                    }

                    session.DeflateLevel = level;
                    return session.WriteAsync($"200 MODE Z LEVEL set to {level}.\r\n", token);
                }

            case "HASH":
                if (!options.Current.Features.Hash)
                {
                    return session.WriteAsync("502 Command not implemented.\r\n"u8, token);
                }

                if (argument.Length == 0)
                {
                    return session.WriteAsync("200 "u8, session.HashAlgorithm, "\r\n"u8, token);
                }

                if (!HashAlgorithms.TryNormalise(argument, out var algorithm))
                {
                    return session.WriteAsync("501 Unknown algorithm, current selection not changed.\r\n"u8, token);
                }

                session.HashAlgorithm = algorithm;
                return session.WriteAsync("200 "u8, algorithm, "\r\n"u8, token);

            default:
                return session.WriteAsync("501 Option not understood.\r\n"u8, token);
        }
    }

    /// <summary>The MLSx fact names this server knows, in the order RFC 3659 lists them.</summary>
    private static readonly (MlsxFacts Flag, string Name)[] FactNames =
    [
        (MlsxFacts.Type, "type"),
        (MlsxFacts.Size, "size"),
        (MlsxFacts.Modify, "modify"),
        (MlsxFacts.Perm, "perm"),
        (MlsxFacts.UnixMode, "UNIX.mode"),
        (MlsxFacts.UnixOwner, "UNIX.owner"),
        (MlsxFacts.UnixGroup, "UNIX.group"),
    ];

    /// <summary>
    /// Renders a fact list. In FEAT every supported fact is listed and an asterisk marks the ones
    /// currently enabled; in an OPTS reply only the names are wanted.
    /// </summary>
    private static string MlsxFactList(MlsxFacts enabled, bool marked = true)
    {
        var builder = new System.Text.StringBuilder();

        foreach (var (flag, name) in FactNames)
        {
            if (!marked && !enabled.HasFlag(flag))
            {
                continue;
            }

            builder.Append(name);

            if (marked && enabled.HasFlag(flag))
            {
                builder.Append('*');
            }

            builder.Append(';');
        }

        return builder.ToString();
    }

    private static bool TryParseFactList(string argument, out MlsxFacts facts)
    {
        facts = MlsxFacts.None;

        // RFC 3659 section 7.9: "where no factname arguments are present, the client is
        // requesting that only the file names be returned".
        if (argument.Length == 0)
        {
            facts = MlsxFacts.None;
            return true;
        }

        // RFC 3659 section 7.9: every fact name is followed by its own semicolon, so the list ends
        // with one and never holds an empty element.
        if (argument[^1] != ';')
        {
            return false;
        }

        foreach (var name in argument[..^1].Split(';'))
        {
            // A doubled semicolon leaves an empty name, and the grammar has no room for one.
            if (name.Length == 0)
            {
                return false;
            }

            // The factlist is semicolon-delimited with no spaces; a space makes it malformed.
            if (name.AsSpan().ContainsAny(' ', '\t'))
            {
                return false;
            }

            foreach (var (flag, known) in FactNames)
            {
                if (string.Equals(name, known, StringComparison.OrdinalIgnoreCase))
                {
                    facts |= flag;
                    break;
                }
            }

            // An unknown fact is silently omitted rather than failing the command.
        }

        return true;
    }

    // ---- HELP -------------------------------------------------------------

    public override ValueTask HelpAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!data.IsEmpty)
        {
            var requested = data.GetString(session.Encoding).Trim().ToUpperInvariant();

            return session.WriteAsync(
                Implemented.Contains(requested)
                    ? $"214 Syntax: {requested}\r\n"
                    : $"502 Unknown command {requested}.\r\n",
                token);
        }

        var lines = new List<string> { "The following commands are recognized:" };

        for (var i = 0; i < Implemented.Length; i += 8)
        {
            lines.Add(" " + string.Join(' ', Implemented.Skip(i).Take(8)));
        }

        return session.WriteMultilineAsync("214", lines, "Help OK.", token);
    }

    private static readonly string[] Implemented =
    [
        "ABOR", "ACCT", "ALLO", "APPE", "AUTH", "AVBL", "CDUP", "CLNT",
        "CSID", "CWD", "DELE", "DSIZ", "EPRT", "EPSV", "FEAT", "HASH",
        "HELP", "HOST", "LANG", "LIST", "LPRT", "LPSV", "MDTM",
        .. (CanSetCreationTime ? (string[])["MFCT"] : []), "MFF", "MFMT",
        "MKD", "MLSD", "MLST", "MODE", "NLST", "NOOP", "OPTS", "PASS",
        "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT", "RANG", "REIN",
        "REST", "RETR", "RMD", "RMDA", "RNFR", "RNTO", "SITE", "SIZE",
        "STAT", "STOR", "STOU", "STRU", "SYST", "TYPE", "USER", "XCRC",
        "XCUP", "XCWD", "XMD5", "XMKD", "XPWD", "XRMD", "XSHA1",
        "XSHA256", "XSHA512",
    ];

    // ---- HOST (RFC 7151) --------------------------------------------------

    public override ValueTask IdentifyVirtualHostAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (session.IsAuthenticated)
        {
            // RFC 7151 section 3.2.3: HOST is only meaningful before authentication.
            return session.WriteAsync("503 Bad sequence of commands: HOST must precede login.\r\n"u8, token);
        }

        if (data.IsEmpty)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        var host = data.GetString(session.Encoding).Trim();

        // RFC 7151 section 4: an additional HOST is treated as though the previous one had never
        // been sent, and resets the authentication environment with it.
        session.VirtualHost = null;
        session.PendingUserName = null;

        if (!TryParseHost(host, out var literal))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        // Section 3.2.1: a literal that is not this server's address is not a host it can serve.
        // The session stays in the no-HOST state (section 3.3 option a) either way. Behind NAT or in
        // a container the address clients use is the public one, not the local endpoint's.
        if (literal is not null && !IsLocalAddress(session, literal) && !IsPublicAddress(literal))
        {
            return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
        }

        // The certificate already presented was chosen for the name in the handshake, so a HOST
        // contradicting it cannot be served. Hardening rather than an RFC 7151 rule; it follows
        // the RFC 4217 section 15.1.1 identity check to its conclusion.
        if (literal is null &&
            session.TlsServerName is { } serverName &&
            !string.Equals(serverName, host, StringComparison.OrdinalIgnoreCase))
        {
            Log.HostContradictsSni(logger, host, serverName);
            return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
        }

        // A single-tenant server accepts any host it can serve and maps it to the same tree.
        session.VirtualHost = host;
        return session.WriteAsync("220 Host accepted.\r\n"u8, token);
    }

    /// <summary>
    /// Parses an RFC 7151 hostname: <c>domain / IP-literal</c>, where an IP-literal is a bare IPv4
    /// address or an IPv6 address in square brackets.
    /// </summary>
    /// <param name="literal">
    /// The address when the hostname is an address literal, for the caller to check against the
    /// server's own; null for a domain name.
    /// </param>
    private static bool TryParseHost(string host, out IPAddress? literal)
    {
        literal = null;

        if (host.Length is 0 or > 255)
        {
            return false;
        }

        if (host[0] == '[')
        {
            // IP-literal = "[" IPv6address "]": no "IPv6:" tag, and no bracketed IPv4.
            if (host[^1] != ']' ||
                !IPAddress.TryParse(host[1..^1], out var parsed) ||
                parsed.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }

            literal = parsed;
            return true;
        }

        if (IPAddress.TryParse(host, out var address) && address.AddressFamily == AddressFamily.InterNetwork)
        {
            literal = address;
            return true;
        }

        return IsDomain(host);
    }

    /// <summary>
    /// domain = sub-domain *("." sub-domain); sub-domain = let-dig [ldh-str];
    /// ldh-str = *( ALPHA / DIGIT / "-" ) let-dig.
    /// </summary>
    private static bool IsDomain(string host)
    {
        foreach (var label in host.Split('.'))
        {
            // An empty label is a leading, trailing or doubled dot.
            if (label.Length is 0 or > 63)
            {
                return false;
            }

            // Only the interior of a label may hold hyphens.
            if (!char.IsAsciiLetterOrDigit(label[0]) || !char.IsAsciiLetterOrDigit(label[^1]))
            {
                return false;
            }

            foreach (var c in label)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c != '-')
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// True when <paramref name="literal"/> is the address this control connection was accepted
    /// on. An unknown local endpoint cannot be contradicted, so it accepts.
    /// </summary>
    private bool IsPublicAddress(IPAddress literal)
        => options.Current.DataConnection.PublicAddress is { Length: > 0 } configured &&
           IPAddress.TryParse(configured, out var publicAddress) &&
           (literal.IsIPv4MappedToIPv6 ? literal.MapToIPv4() : literal).Equals(
               publicAddress.IsIPv4MappedToIPv6 ? publicAddress.MapToIPv4() : publicAddress);

    private static bool IsLocalAddress(FtpSession session, IPAddress literal)
    {
        if ((session.LocalEndPoint as IPEndPoint)?.Address is not { } local)
        {
            return true;
        }

        // A dual-stack listener reports IPv4 peers as ::ffff:a.b.c.d.
        return literal.Equals(local) ||
               (literal.IsIPv4MappedToIPv6 ? literal.MapToIPv4() : literal).Equals(
                   local.IsIPv4MappedToIPv6 ? local.MapToIPv4() : local);
    }

    // ---- LANG (RFC 2640) --------------------------------------------------

    public override ValueTask LanguageNegotiationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (data.IsEmpty)
        {
            // No argument resets to the default language.
            return session.WriteAsync("200 Language set to EN.\r\n"u8, token);
        }

        var language = data.GetString(session.Encoding).Trim();

        // Only English is available, so anything else must be refused rather than silently ignored.
        return language.StartsWith("EN", StringComparison.OrdinalIgnoreCase)
            ? session.WriteAsync("200 Language set to EN.\r\n"u8, token)
            : session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
    }

    // ---- SITE -------------------------------------------------------------

    public override ValueTask SiteSpecificCommandsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!options.Current.Features.Site)
        {
            return session.WriteAsync("502 Command not implemented.\r\n"u8, token);
        }

        if (data.IsEmpty)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        var text = data.GetString(session.Encoding).Trim();
        var space = text.IndexOf(' ');
        var verb = (space < 0 ? text : text[..space]).ToUpperInvariant();
        var argument = space < 0 ? string.Empty : text[(space + 1)..].Trim();

        switch (verb)
        {
            case "HELP":
                return session.WriteMultilineAsync("214", ["The following SITE commands are recognized:", " " + string.Join(' ', SiteCommands())], "Help OK.", token);

            case "CHMOD":
                return SiteChmodAsync(session, argument, token);

            case "SYMLINK" when options.Current.Features.SiteSymlink:
                return SiteSymlinkAsync(session, argument, token);

            case "UTIME":
                return SiteUtimeAsync(session, argument, token);

            default:
                return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
        }
    }

    /// <summary>The SITE sub-commands on offer, as FEAT and SITE HELP list them.</summary>
    private IEnumerable<string> SiteCommands()
    {
        yield return "CHMOD";
        yield return "HELP";

        if (options.Current.Features.SiteSymlink)
        {
            yield return "SYMLINK";
        }

        yield return "UTIME";
    }

    private ValueTask SiteChmodAsync(FtpSession session, string argument, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.SiteSpecificCommands, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        var space = argument.IndexOf(' ');

        if (space < 0)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        var modeText = argument[..space];

        // Permission bits only: setuid, setgid and sticky are not something an FTP user gets to set.
        if (modeText.Length is < 3 or > 4 || !TryParseOctal(modeText, out var mode) || mode > MaxPermissionBits)
        {
            return session.WriteAsync("501 Invalid mode.\r\n"u8, token);
        }

        if (!SequenceExtensions.TryResolvePath(argument[(space + 1)..], session.CurrentDirectory, out var path))
        {
            return session.WriteAsync("550 Invalid path.\r\n"u8, token);
        }

        if (path == UPath.Root)
        {
            return session.WriteAsync("550 Requested action not taken: the mode of the root directory cannot be changed.\r\n"u8, token);
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (!session.FileSystem.FileExists(path) && !session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        // A remote tree has no host path to chmod, which is the same as having no mode bits.
        if (OperatingSystem.IsWindows() || !FtpFileSystemCapabilities.HasHostPath(session.FileSystem, path))
        {
            // Windows has no Unix mode bits. The default is a 200 that says the mode was ignored,
            // because clients that copy permissions on upload otherwise fail every transfer; an
            // operator who prefers the strict answer gets the 504.
            return options.Current.Features.IgnoreUnsupportedChmod
                ? session.WriteAsync("200 SITE CHMOD ignored: this platform has no Unix permissions.\r\n"u8, token)
                : session.WriteAsync("504 CHMOD is not supported on this platform.\r\n"u8, token);
        }

        try
        {
            var internalPath = session.FileSystem.ConvertPathToInternal(path);
            File.SetUnixFileMode(internalPath, (UnixFileMode)mode);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("200 SITE CHMOD command successful.\r\n"u8, token);
    }

    private ValueTask SiteUtimeAsync(FtpSession session, string argument, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.SiteSpecificCommands, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        if (!TryParseSiteUtime(session, argument, out var request))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        if (request.Path is not { } path)
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        try
        {
            session.FileSystem.SetLastWriteTime(path, request.Modify.UtcDateTime);

            if (request.Access is { } access)
            {
                session.FileSystem.SetLastAccessTime(path, access.UtcDateTime);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("200 SITE UTIME command successful.\r\n"u8, token);
    }

    /// <summary>A parsed SITE UTIME. <see cref="Path"/> is null when the named object does not exist.</summary>
    private readonly record struct SiteUtimeRequest(UPath? Path, DateTimeOffset Modify, DateTimeOffset? Access);

    /// <summary>
    /// Parses the three SITE UTIME forms clients send, none of them standardised.
    /// </summary>
    /// <remarks>
    /// <list type="number">
    /// <item><c>&lt;path&gt; &lt;atime&gt; &lt;mtime&gt; &lt;ctime&gt; UTC</c> - Pure-FTPd and vsftpd forks, WinSCP.</item>
    /// <item><c>&lt;YYYYMMDDhhmm[ss]&gt; &lt;path&gt;</c> - ProFTPD mod_site_misc, time first.</item>
    /// <item><c>&lt;path&gt; &lt;time-val&gt;</c> - the order this server accepted originally.</item>
    /// </list>
    /// Pathnames may contain spaces, so the forms are told apart by the shape of the tokens at the
    /// ends. When both single-timestamp readings parse, the one naming an existing object wins.
    /// Returns false only for a syntax error; a well-formed request for a missing object comes back
    /// with a null path.
    /// </remarks>
    private static bool TryParseSiteUtime(FtpSession session, string argument, out SiteUtimeRequest request)
    {
        request = default;

        var tokens = argument.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (tokens.Length < 2)
        {
            return false;
        }

        if (tokens.Length >= 5 &&
            tokens[^1].Equals("UTC", StringComparison.OrdinalIgnoreCase) &&
            TryParseSiteTime(tokens[^4], out var access) &&
            TryParseSiteTime(tokens[^3], out var modify) &&
            TryParseSiteTime(tokens[^2], out _))
        {
            // The pathname is whatever precedes the four trailing tokens, spaces and all.
            var pathText = argument.TrimEnd();

            for (var i = 0; i < 4; i++)
            {
                pathText = pathText[..pathText.LastIndexOf(' ')].TrimEnd();
            }

            request = new SiteUtimeRequest(Existing(session, pathText), modify, access);
            return true;
        }

        var timeFirst = TryParseSiteTime(tokens[0], out var leadingTime)
            ? Existing(session, argument[tokens[0].Length..].TrimStart())
            : null;

        var lastSpace = argument.LastIndexOf(' ');
        var timeLast = TryParseSiteTime(argument[(lastSpace + 1)..], out var trailingTime)
            ? Existing(session, argument[..lastSpace].TrimEnd())
            : null;

        if (timeFirst is not null)
        {
            request = new SiteUtimeRequest(timeFirst, leadingTime, null);
            return true;
        }

        if (timeLast is not null)
        {
            request = new SiteUtimeRequest(timeLast, trailingTime, null);
            return true;
        }

        // Well-formed but naming nothing: report the missing object rather than the syntax.
        if (TryParseSiteTime(tokens[0], out leadingTime) || TryParseSiteTime(tokens[^1], out trailingTime))
        {
            request = new SiteUtimeRequest(null, default, null);
            return true;
        }

        return false;

        static UPath? Existing(FtpSession session, string pathText)
        {
            if (pathText.Length == 0 ||
                !SequenceExtensions.TryResolvePath(pathText, session.CurrentDirectory, out var path))
            {
                return null;
            }

            // The cast matters: a bare null would convert to an empty UPath through its implicit
            // conversion from string, rather than to "no path".
            return session.FileSystem.FileExists(path) || session.FileSystem.DirectoryExists(path)
                ? path
                : (UPath?)null;
        }
    }

    /// <summary>
    /// A SITE UTIME timestamp: an RFC 3659 time-val, or ProFTPD's minute-precision
    /// YYYYMMDDhhmm. Always UTC.
    /// </summary>
    private static bool TryParseSiteTime(string value, out DateTimeOffset timestamp)
    {
        if (value.Length == 12 && value.AsSpan().IndexOfAnyExceptInRange('0', '9') < 0)
        {
            value += "00";
        }

        return TryParseTimeVal(value, out timestamp);
    }

    /// <summary>
    /// SITE SYMLINK &lt;target&gt; &lt;link&gt; (ProFTPD mod_site_misc; Beyond Compare quotes both).
    /// </summary>
    /// <remarks>
    /// The target is resolved like any other pathname - relative to the link's directory, clamped
    /// at the root - and must already exist, inside the same mount as the link. The link stores a
    /// relative path, so it survives the tree being moved, and can never name anything the session
    /// could not reach through the tree itself. Reading through it is still subject to the jail.
    /// </remarks>
    private ValueTask SiteSymlinkAsync(FtpSession session, string argument, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.SiteSpecificCommands, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        if (!TrySplitTwoPathnames(argument, out var targetText, out var linkText) ||
            !SequenceExtensions.TryResolvePath(linkText, session.CurrentDirectory, out var link) ||
            link == UPath.Root ||
            !SequenceExtensions.TryResolvePath(targetText, link.GetDirectory(), out var target))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        if (TryRejectReadOnlyPath(session, link, out readOnly))
        {
            return readOnly;
        }

        var fileSystem = session.FileSystem;

        // A link is made on the host, and a remote tree has no host path to make it at.
        if (!FtpFileSystemCapabilities.HasHostPath(fileSystem, link) || !FtpFileSystemCapabilities.HasHostPath(fileSystem, target))
        {
            return session.WriteAsync("550 Requested action not taken: links cannot be created here.\r\n"u8, token);
        }

        var targetIsDirectory = fileSystem.DirectoryExists(target);

        if (!targetIsDirectory && !fileSystem.FileExists(target))
        {
            return session.WriteAsync("550 Link target not found.\r\n"u8, token);
        }

        if (fileSystem.FileExists(link) || fileSystem.DirectoryExists(link))
        {
            return session.WriteAsync("553 Requested action not taken: the link name already exists.\r\n"u8, token);
        }

        if (!fileSystem.DirectoryExists(link.GetDirectory()))
        {
            return session.WriteAsync("550 Directory not found.\r\n"u8, token);
        }

        // Each mount is its own physical tree, so a link from one into another would land outside
        // the tree that contains it - which the link check then refuses to follow anyway.
        if (fileSystem is Zio.FileSystems.MountFileSystem mounts)
        {
            // An unmounted path belongs to the home tree, and comes back with no mount name.
            mounts.TryGetMount(link, out var linkMount, out _, out _);
            mounts.TryGetMount(target, out var targetMount, out _, out _);

            if (linkMount != targetMount)
            {
                return session.WriteAsync("550 Requested action not taken: the link and its target are in different folders.\r\n"u8, token);
            }
        }

        try
        {
            // Both conversions run the containment check, so neither end can name a host path
            // outside the tree.
            var linkPath = fileSystem.ConvertPathToInternal(link);
            var targetPath = fileSystem.ConvertPathToInternal(target);
            var relative = Path.GetRelativePath(Path.GetDirectoryName(linkPath)!, targetPath);

            if (targetIsDirectory)
            {
                Directory.CreateSymbolicLink(linkPath, relative);
            }
            else
            {
                File.CreateSymbolicLink(linkPath, relative);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // On Windows, creating a symbolic link needs Developer Mode or the privilege for it.
            return session.WriteAsync("550 Requested action not taken: the link could not be created.\r\n"u8, token);
        }

        return session.WriteAsync("200 SITE SYMLINK command successful.\r\n"u8, token);
    }

    /// <summary>
    /// Splits "&lt;a&gt; &lt;b&gt;" where either may be quoted (with "" for a literal quote). An
    /// unquoted last argument takes the rest of the line, spaces included. The quotes are kept, for
    /// the path resolver to remove.
    /// </summary>
    private static bool TrySplitTwoPathnames(string argument, out string first, out string second)
    {
        first = second = string.Empty;
        argument = argument.Trim();

        int end;

        if (argument.StartsWith('"'))
        {
            end = 1;

            while (true)
            {
                end = argument.IndexOf('"', end);

                if (end < 0)
                {
                    return false;
                }

                // A doubled quote is a literal quote inside the name.
                if (end + 1 < argument.Length && argument[end + 1] == '"')
                {
                    end += 2;
                    continue;
                }

                end++;
                break;
            }
        }
        else
        {
            end = argument.IndexOf(' ');

            if (end < 0)
            {
                return false;
            }
        }

        first = argument[..end];
        second = argument[end..].Trim();
        return first.Length > 0 && second.Length > 0;
    }

    /// <summary>The permission bits a client may set: 0777, without setuid, setgid or sticky.</summary>
    private const int MaxPermissionBits = 0x1FF;

    private static bool TryParseOctal(string value, out int result)
    {
        result = 0;

        foreach (var c in value)
        {
            if (c is < '0' or > '7')
            {
                return false;
            }

            result = (result * 8) + (c - '0');
        }

        return true;
    }

    // ---- intentionally not implemented ------------------------------------

    public override ValueTask GetThumbnailAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    public override ValueTask ClientServerIdentificationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // draft-peterson-streamlined section 6.2 requires 530 when not logged in, and the
        // response facts to be semicolon-terminated with CaseSensitive present.
        if (TryRejectAnonymous(session, FtpCommand.ClientServerIdentification, out var rejected))
        {
            return rejected;
        }

        var caseSensitive = OperatingSystem.IsWindows() ? "N" : "Y";
        return session.WriteAsync($"200 Name=FtpServer; CaseSensitive={caseSensitive};\r\n", token);
    }

    public override ValueTask XRemoteCopyAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    public override ValueTask XRemoteSearchQueryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    public override ValueTask SendOrMailAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    public override ValueTask SendToTerminalAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);
}
