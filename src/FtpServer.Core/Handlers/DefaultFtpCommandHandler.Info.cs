using System.Buffers;
using System.Net;
using System.Net.Sockets;
using FtpServer.Extensions;

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

        if (options.Current.Ftps)
        {
            // RFC 4217 section 6 requires all three to be advertised.
            lines.Add(" AUTH TLS");
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
            lines.Add(" SITE CHMOD;HELP;UTIME");
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
                    session.Encoding = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
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
        "HELP", "HOST", "LANG", "LIST", "LPRT", "LPSV", "MDTM", "MFMT",
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
        // The session stays in the no-HOST state (section 3.3 option a) either way.
        if (literal is not null && !IsLocalAddress(session, literal))
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
                return session.WriteMultilineAsync("214", ["The following SITE commands are recognized:", " CHMOD HELP UTIME"], "Help OK.", token);

            case "CHMOD":
                return SiteChmodAsync(session, argument, token);

            case "UTIME":
                return SiteUtimeAsync(session, argument, token);

            default:
                return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
        }
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

        if (modeText.Length is < 3 or > 4 || !TryParseOctal(modeText, out var mode))
        {
            return session.WriteAsync("501 Invalid mode.\r\n"u8, token);
        }

        if (!SequenceExtensions.TryResolvePath(argument[(space + 1)..], session.CurrentDirectory, out var path))
        {
            return session.WriteAsync("550 Invalid path.\r\n"u8, token);
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (!session.FileSystem.FileExists(path) && !session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        if (OperatingSystem.IsWindows())
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

        // SITE UTIME <pathname> <time-val> (the widely implemented single-timestamp form).
        var space = argument.LastIndexOf(' ');

        if (space < 0)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        if (!TryParseTimeVal(argument[(space + 1)..], out var timestamp))
        {
            return session.WriteAsync("501 Invalid time-val.\r\n"u8, token);
        }

        if (!SequenceExtensions.TryResolvePath(argument[..space], session.CurrentDirectory, out var path))
        {
            return session.WriteAsync("550 Invalid path.\r\n"u8, token);
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (!session.FileSystem.FileExists(path) && !session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        try
        {
            session.FileSystem.SetLastWriteTime(path, timestamp.UtcDateTime);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("200 SITE UTIME command successful.\r\n"u8, token);
    }

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
