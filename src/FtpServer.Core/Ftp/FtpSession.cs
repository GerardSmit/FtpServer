using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using FtpServer.Authentication;
using FtpServer.Data;
using FtpServer.Utils;
using Zio;
using Zio.FileSystems;

namespace FtpServer;

public sealed class FtpSession(
    IDuplexPipe pipe,
    IServiceProvider provider,
    IFileSystem fileSystem
) : IAsyncDisposable
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private bool _disposed;

    public FtpDataStreamProvider DataStreamProvider { get; set; } = FtpDataStreamProvider.Active;

    public UPath CurrentDirectory { get; set; } = UPath.Root;

    /// <summary>
    /// Value negotiated by PBSZ. RFC 4217 requires 0 for TLS, which is the only value we accept.
    /// </summary>
    public int BufferSize { get; set; }

    /// <summary>
    /// Set once PBSZ has been accepted; PROT is only valid afterwards (RFC 2228 section 3).
    /// </summary>
    public bool ProtectionBufferNegotiated { get; set; }

    public IPEndPoint? ActiveDataIp { get; set; }

    public IServiceProvider RootServiceProvider { get; } = provider;

    public IFileSystem FileSystem { get; private set; } = fileSystem;

    /// <summary>
    /// Control-connection encoding. UTF-8 is the RFC 2640 default; OPTS UTF8 OFF reverts to ASCII.
    /// </summary>
    /// <remarks>
    /// Invalid sequences throw rather than becoming U+FFFD: RFC 2640 section 3.1 requires a
    /// pathname to be checked for validity, and replacement would alias distinct byte strings onto
    /// one value.
    /// </remarks>
    public static Encoding DefaultEncoding { get; } = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public const string DefaultHashAlgorithm = "SHA-256";

    /// <summary>
    /// RFC 959 sections 3.1.1 and 5.1 make ASCII Non-print the representation type in force until
    /// a client says otherwise, and RFC 1123 keeps it in the minimum implementation.
    /// </summary>
    public const FtpTransferType DefaultTransferType = FtpTransferType.Ascii;

    public Encoding Encoding { get; set; } = DefaultEncoding;

    public IDuplexPipe Transport { get; set; } = pipe;

    public FtpDataConnectionMode DataConnectionMode { get; set; } = FtpDataConnectionMode.Clear;

    public EndPoint? RemoteEndPoint { get; set; }

    public EndPoint? LocalEndPoint { get; set; }

    /// <summary>True once the control connection has been upgraded by AUTH TLS.</summary>
    public bool IsProtected { get; set; }

    /// <summary>
    /// True for a connection to the implicit FTPS port: TLS from the first byte, which REIN does
    /// not drop and AUTH cannot renegotiate.
    /// </summary>
    public bool IsImplicitTls { get; set; }

    // ---- login state ------------------------------------------------------

    public bool IsAuthenticated { get; private set; }

    public FtpUser? User { get; private set; }

    /// <summary>User name supplied by USER and awaiting a PASS.</summary>
    public string? PendingUserName { get; set; }

    public void SignIn(FtpUser user)
    {
        User = user;
        IsAuthenticated = true;
        PendingUserName = null;
    }

    /// <summary>Drops the authenticated identity, leaving everything else alone.</summary>
    public void SignOut()
    {
        User = null;
        IsAuthenticated = false;
        PendingUserName = null;
    }

    /// <summary>
    /// Returns the session to the state a fresh login starts from: no identity, and the transfer
    /// parameters back at their defaults.
    /// </summary>
    /// <remarks>
    /// The set is the one RFC 4217 section 4 lists - user identity, default data ports, TYPE,
    /// STRU, MODE and current working directory - which is also what a second USER (RFC 959
    /// section 5.4) must not let a client inherit.
    ///
    /// EpsvAll is deliberately not reset: RFC 2428 section 4 latches it "for the remainder of the
    /// session". VirtualHost survives too, being scoped to the connection rather than the login.
    /// </remarks>
    public void ResetForNewUser()
    {
        SignOut();

        CurrentDirectory = UPath.Root;
        RenameFrom = null;
        RestartOffset = 0;
        TransferType = DefaultTransferType;
        TransferMode = FtpTransferMode.Stream;
        DeflateLevel = DefaultDeflateLevel;
        ActiveDataIp = null;
        HashRange = null;
        DataStreamProvider = FtpDataStreamProvider.Active;
    }

    /// <summary>Resets the parts of the session that REIN must clear but a second USER must not.</summary>
    /// <remarks>
    /// RFC 4217 section 13 also requires the TLS session to be cleared and both channels to revert
    /// to the clear, which the connection handler completes once the 220 has been written.
    /// </remarks>
    public void ResetForReinitialize()
    {
        ResetForNewUser();

        EpsvAll = false;
        EnabledFacts = MlsxFacts.Default;
        VirtualHost = null;
        Encoding = DefaultEncoding;
        HashAlgorithm = DefaultHashAlgorithm;

        // An implicit connection keeps its TLS session through REIN, and with it the name the
        // client asked for in the handshake.
        if (!IsImplicitTls)
        {
            TlsServerName = null;
        }

        ResetProtectionParameters();
    }

    /// <summary>
    /// Forgets the PBSZ/PROT negotiation: data connections go back to the clear, or on an
    /// implicit connection to the protected default that connection started with.
    /// </summary>
    public void ResetProtectionParameters()
    {
        BufferSize = 0;

        // Implicit FTPS clients expect protected data connections without asking, and some send
        // PROT without the PBSZ that would otherwise have to come first.
        ProtectionBufferNegotiated = IsImplicitTls;
        DataConnectionMode = IsImplicitTls ? FtpDataConnectionMode.Private : FtpDataConnectionMode.Clear;
    }

    public bool CanWrite => !IsReadOnly;

    public bool IsReadOnly { get; set; }

    /// <summary>
    /// Whether <paramref name="path"/> may be modified: the session has to be writable, and the
    /// path must not fall inside a folder that was mounted read-only.
    /// </summary>
    /// <remarks>
    /// Asked before a command acts, so a read-only mount is refused with 550 rather than failing
    /// once the data connection is already open - which is the illegal "150 then error" sequence
    /// the transfer code takes care to avoid everywhere else.
    /// </remarks>
    public bool CanWriteTo(UPath path) => CanWrite && !IsReadOnlyMount(FileSystem, path);

    private static bool IsReadOnlyMount(IFileSystem fileSystem, UPath path) =>
        fileSystem is MountFileSystem mounts &&
        path.IsAbsolute &&
        mounts.TryGetMount(path, out _, out var target, out _) &&
        target is ReadOnlyFileSystem;

    public void ReplaceFileSystem(IFileSystem newFileSystem)
    {
        var previous = FileSystem;
        FileSystem = newFileSystem;

        if (!ReferenceEquals(previous, newFileSystem))
        {
            previous.Dispose();
        }
    }

    // ---- transfer state ---------------------------------------------------

    public FtpTransferType TransferType { get; set; } = DefaultTransferType;

    /// <summary>Set by MODE; Deflate compresses the data connection (MODE Z).</summary>
    public FtpTransferMode TransferMode { get; set; }

    /// <summary>zlib compression level for MODE Z, set with "OPTS MODE Z LEVEL n" (0-9).</summary>
    public int DeflateLevel { get; set; } = DefaultDeflateLevel;

    public const int DefaultDeflateLevel = 6;

    /// <summary>Pathname captured by RNFR, awaiting RNTO.</summary>
    public UPath? RenameFrom { get; set; }

    /// <summary>Marker set by REST; consumed and reset by the next transfer command.</summary>
    public long RestartOffset { get; set; }

    /// <summary>Set by "EPSV ALL"; makes PORT/EPRT/PASV illegal for the rest of the session.</summary>
    public bool EpsvAll { get; set; }

    /// <summary>Cancels the transfer currently in flight, for ABOR.</summary>
    public CancellationTokenSource? TransferCancellation { get; set; }

    /// <summary>Algorithm used by HASH, selected with "OPTS HASH".</summary>
    public string HashAlgorithm { get; set; } = DefaultHashAlgorithm;

    /// <summary>Byte range set by RANG and consumed by the next HASH.</summary>
    public (long Start, long End)? HashRange { get; set; }

    /// <summary>Virtual host named by HOST (RFC 7151).</summary>
    public string? VirtualHost { get; set; }

    /// <summary>
    /// Server name the client sent in the TLS handshake, when it sent one.
    /// </summary>
    /// <remarks>
    /// A HOST naming a different server contradicts it, and honouring both is how one tenant's
    /// tree ends up served under another tenant's certificate.
    /// </remarks>
    public string? TlsServerName { get; set; }

    /// <summary>
    /// Set by a handler that has replied 421; the connection handler closes once the reply is out.
    /// </summary>
    /// <remarks>
    /// 421 means "service not available, closing control connection", so leaving the connection
    /// open after sending one contradicts the reply.
    /// </remarks>
    public bool CloseRequested { get; set; }

    /// <summary>
    /// Set by REIN once its 220 has been written inside the protected connection; the connection
    /// handler then tears the TLS session down and continues in the clear (RFC 4217 section 13).
    /// </summary>
    public bool ClearProtectionRequested { get; set; }

    /// <summary>
    /// Facts MLSx should emit, as narrowed by "OPTS MLST" (RFC 3659 section 7.9).
    /// </summary>
    public MlsxFacts EnabledFacts { get; set; } = MlsxFacts.Default;

    // ---- replies ----------------------------------------------------------

    private async ValueTask WriteCoreAsync(ReadOnlyMemory<byte> data, CancellationToken token)
    {
        await _writeLock.WaitAsync(token).ConfigureAwait(false);

        try
        {
            Transport.Output.Write(data.Span);
            await Transport.Output.FlushAsync(token).GetAsValueTask().ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> data, CancellationToken token = default)
    {
        // Replies are small; copying lets the write be serialised behind an async lock,
        // which a ReadOnlySpan parameter could not cross.
        var buffer = GC.AllocateUninitializedArray<byte>(data.Length);
        data.CopyTo(buffer);
        return WriteCoreAsync(buffer, token);
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> data, ReadOnlySpan<byte> data2, CancellationToken token = default)
    {
        var buffer = GC.AllocateUninitializedArray<byte>(data.Length + data2.Length);
        data.CopyTo(buffer);
        data2.CopyTo(buffer.AsSpan(data.Length));
        return WriteCoreAsync(buffer, token);
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> data, ReadOnlySpan<byte> data2, ReadOnlySpan<byte> data3, CancellationToken token = default)
    {
        var buffer = GC.AllocateUninitializedArray<byte>(data.Length + data2.Length + data3.Length);
        data.CopyTo(buffer);
        data2.CopyTo(buffer.AsSpan(data.Length));
        data3.CopyTo(buffer.AsSpan(data.Length + data2.Length));
        return WriteCoreAsync(buffer, token);
    }

    public ValueTask WriteAsync(string data, CancellationToken token = default)
    {
        var buffer = GC.AllocateUninitializedArray<byte>(Encoding.GetByteCount(data));
        var length = Encoding.GetBytes(data, buffer);
        return WriteCoreAsync(buffer.AsMemory(0, length), token);
    }

    public ValueTask WriteAsync(ReadOnlySpan<byte> prefix, string value, ReadOnlySpan<byte> suffix, CancellationToken token = default)
    {
        var buffer = GC.AllocateUninitializedArray<byte>(prefix.Length + Encoding.GetByteCount(value) + suffix.Length);

        prefix.CopyTo(buffer);
        var length = Encoding.GetBytes(value, buffer.AsSpan(prefix.Length));
        suffix.CopyTo(buffer.AsSpan(prefix.Length + length));

        return WriteCoreAsync(buffer.AsMemory(0, prefix.Length + length + suffix.Length), token);
    }

    public ValueTask WritePassiveModeAsync(ReadOnlySpan<byte> data, IPAddress address, int a, int b, ReadOnlySpan<byte> suffix, CancellationToken token = default)
    {
        Span<byte> scratch = stackalloc byte[64];

        if (!address.TryFormat(scratch, out var written))
        {
            throw new InvalidOperationException("Failed to format IP address");
        }

        for (var i = 0; i < written; i++)
        {
            if (scratch[i] == '.')
            {
                scratch[i] = (byte)',';
            }
        }

        var buffer = GC.AllocateUninitializedArray<byte>(data.Length + written + 12 + suffix.Length);
        var span = buffer.AsSpan();

        data.CopyTo(span);
        var total = data.Length;

        scratch[..written].CopyTo(span[total..]);
        total += written;

        span[total++] = (byte)',';
        a.TryFormat(span[total..], out written);
        total += written;

        span[total++] = (byte)',';
        b.TryFormat(span[total..], out written);
        total += written;

        suffix.CopyTo(span[total..]);
        total += suffix.Length;

        return WriteCoreAsync(buffer.AsMemory(0, total), token);
    }

    public ValueTask WriteExtendedPassiveModeAsync(ReadOnlySpan<byte> data, int port, ReadOnlySpan<byte> suffix, CancellationToken token = default)
    {
        // |||port|  -- 3 leading delimiters, up to 5 port digits, 1 trailing delimiter
        var buffer = GC.AllocateUninitializedArray<byte>(data.Length + 3 + 5 + 1 + suffix.Length);
        var span = buffer.AsSpan();

        data.CopyTo(span);
        var total = data.Length;

        span[total++] = (byte)'|';
        span[total++] = (byte)'|';
        span[total++] = (byte)'|';

        port.TryFormat(span[total..], out var written);
        total += written;

        span[total++] = (byte)'|';

        suffix.CopyTo(span[total..]);
        total += suffix.Length;

        return WriteCoreAsync(buffer.AsMemory(0, total), token);
    }

    /// <summary>
    /// Writes a multi-line reply in the RFC 959 section 4.2 "xyz-" ... "xyz " form, escaping any
    /// continuation line that would otherwise look like a terminator.
    /// </summary>
    /// <remarks>
    /// RFC 959 section 4.2: only the first line carries "code-" and only the last carries
    /// "code "; the lines between are sent verbatim. RFC 2389 depends on that exact shape, since
    /// a FEAT feature is identified by its single leading space.
    /// </remarks>
    public ValueTask WriteMultilineAsync(string code, IReadOnlyList<string> lines, string final, CancellationToken token = default)
    {
        if (lines.Count == 0)
        {
            return WriteAsync($"{code} {Sanitise(final)}\r\n", token);
        }

        var sb = new StringBuilder();

        sb.Append(code).Append('-').Append(Sanitise(lines[0])).Append("\r\n");

        for (var i = 1; i < lines.Count; i++)
        {
            AppendContinuation(sb, lines[i]);
        }

        sb.Append(code).Append(' ').Append(Sanitise(final)).Append("\r\n");

        return WriteAsync(sb.ToString(), token);

        static void AppendContinuation(StringBuilder target, string line)
        {
            var text = Sanitise(line);

            // A continuation line beginning with three digits could be mistaken for the
            // terminator, so it is padded with a leading space.
            if (text.Length >= 3 && char.IsAsciiDigit(text[0]) && char.IsAsciiDigit(text[1]) && char.IsAsciiDigit(text[2]))
            {
                target.Append(' ');
            }

            target.Append(text).Append("\r\n");
        }

        static string Sanitise(string line)
        {
            // A CR or LF inside a reply line would forge an extra reply.
            return line.Replace('\r', ' ').Replace('\n', ' ');
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            TransferCancellation?.Cancel();
        }
        catch
        {
            // Ignore
        }

        // Releases any rented passive port and closes a half-open data connection.
        await DataStreamProvider.ReleaseAsync().ConfigureAwait(false);

        TransferCancellation?.Dispose();
        _writeLock.Dispose();
        FileSystem.Dispose();
    }
}

public enum FtpTransferMode
{
    /// <summary>MODE S - the file as a plain byte stream, ended by closing the connection.</summary>
    Stream,

    /// <summary>MODE Z - the stream compressed with zlib (RFC 1950/1951).</summary>
    Deflate,
}

public enum FtpTransferType
{
    /// <summary>TYPE A - line endings are translated to CRLF on the wire.</summary>
    Ascii,

    /// <summary>TYPE I - bytes are passed through untouched.</summary>
    Image,
}

/// <summary>
/// The MLSx facts a session emits. RFC 3659 section 7.9 lets a client narrow the set with
/// "OPTS MLST", after which the server must emit only what was asked for.
/// </summary>
[Flags]
public enum MlsxFacts
{
    None = 0,
    Type = 1 << 0,
    Size = 1 << 1,
    Modify = 1 << 2,
    Perm = 1 << 3,
    UnixMode = 1 << 4,
    UnixOwner = 1 << 5,
    UnixGroup = 1 << 6,

    /// <summary>
    /// What a session emits until the client narrows or widens the set with OPTS MLST.
    /// </summary>
    /// <remarks>
    /// UNIX.owner and UNIX.group are supported but off by default: they are the expensive facts
    /// (an account lookup per owner) and many clients never send OPTS MLST, so they would pay for
    /// facts they do not parse.
    /// </remarks>
    Default = Type | Size | Modify | Perm | UnixMode,
}
