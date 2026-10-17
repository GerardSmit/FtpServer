using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FtpServer.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpServer;

public sealed class CertificateProvider(
    IOptions<FtpOptions> options,
    ILogger<CertificateProvider> logger
) : IDisposable
{
    private readonly Lock _gate = new();
    private X509Certificate2? _certificate;
    private X509Certificate2Collection? _intermediates;
    private SslStreamCertificateContext? _certificateContext;
    private bool _disposed;

    /// <summary>
    /// Loads and checks the certificate now, rather than on the first client's handshake.
    /// </summary>
    /// <remarks>
    /// A PFX with the wrong format, password or no private key otherwise fails after the server
    /// has answered 234 and committed the client to a handshake - once per client, only in the log.
    /// </remarks>
    public void Validate()
    {
        var certificate = GetCertificate();

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"The TLS certificate '{certificate.Subject}' has no private key, so it cannot be used to serve FTPS.");
        }

        // Builds the chain as well, which is the other half of what a handshake needs.
        GetCertificateContext();
    }

    public X509Certificate2 GetCertificate()
    {
        if (_certificate is { } existing)
        {
            return existing;
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _certificate ??= Load();
        }
    }

    /// <summary>
    /// The certificate context shared by every handshake, control and data alike.
    /// </summary>
    /// <remarks>
    /// Building it once means the certificate chain is resolved once for the process rather than
    /// on every handshake. Session resumption does not depend on this - .NET's credential cache
    /// already unifies handshakes that present the same certificate, which is what lets a data
    /// connection resume the control connection's TLS session (see tools/verify-tls-resumption.sh).
    /// </remarks>
    public SslStreamCertificateContext GetCertificateContext()
    {
        if (_certificateContext is { } existing)
        {
            return existing;
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            // The intermediates come from the PFX. Without them the chain is whatever the machine
            // store holds, and offline: true means nothing is fetched to fill the gap.
            var certificate = GetCertificate();

            return _certificateContext ??= SslStreamCertificateContext.Create(
                certificate,
                _intermediates,
                offline: true);
        }
    }

    public SslServerAuthenticationOptions CreateServerAuthenticationOptions() => new()
    {
        ServerCertificateContext = GetCertificateContext(),
        EnabledSslProtocols = ResolveProtocols(),
        ClientCertificateRequired = false,
        AllowTlsResume = options.Value.Certificate.AllowTlsResume,
    };

    private SslProtocols ResolveProtocols()
    {
        var configured = options.Value.Certificate.MinimumProtocol;

        if (string.IsNullOrWhiteSpace(configured))
        {
            // Let OS policy decide, so the server keeps current as weak versions are retired.
            return SslProtocols.None;
        }

        return TryParseProtocols(configured, out var protocols)
            ? protocols
            // Unreachable once validated, and deliberately not a fallback: the OS default would
            // answer a request for TLS 1.3 by quietly re-enabling TLS 1.2.
            : throw new InvalidOperationException($"Unknown minimum TLS protocol '{configured}'.");
    }

    /// <summary>Parses a configured minimum TLS version, for both use and startup validation.</summary>
    public static bool TryParseProtocols(string? configured, out SslProtocols protocols)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            protocols = SslProtocols.None;
            return true;
        }

        switch (configured.Replace(".", string.Empty).ToUpperInvariant())
        {
            case "TLS12" or "TLS1_2" or "12":
                protocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                return true;

            case "TLS13" or "TLS1_3" or "13":
                protocols = SslProtocols.Tls13;
                return true;

            default:
                protocols = SslProtocols.None;
                return false;
        }
    }

    private X509Certificate2 Load()
    {
        var certificate = options.Value.Certificate;

        if (!string.IsNullOrWhiteSpace(certificate.Path))
        {
            Log.LoadingCertificate(logger, certificate.Path);

            // Loaded as a collection: a PFX usually bundles the issuing chain alongside the leaf.
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                certificate.Path,
                certificate.Password,
                X509KeyStorageFlags.Exportable);

            var leaf = SelectLeaf(collection);
            var intermediates = new X509Certificate2Collection();

            foreach (var candidate in collection)
            {
                if (!ReferenceEquals(candidate, leaf))
                {
                    intermediates.Add(candidate);
                }
            }

            _intermediates = intermediates.Count > 0 ? intermediates : null;
            return leaf;
        }

        Log.GeneratingSelfSignedCertificate(logger, certificate.SelfSignedSubject);

        return CreateSelfSignedCertificate(certificate.SelfSignedSubject, 2048);
    }

    /// <summary>
    /// Picks the certificate the server presents: the one with a private key, since that is the
    /// only one it can prove it owns.
    /// </summary>
    private static X509Certificate2 SelectLeaf(X509Certificate2Collection collection)
    {
        if (collection.Count == 0)
        {
            throw new InvalidOperationException("The certificate file contains no certificates.");
        }

        foreach (var candidate in collection)
        {
            if (candidate.HasPrivateKey)
            {
                return candidate;
            }
        }

        // Nothing has a key; return the first so Validate reports that plainly.
        return collection[0];
    }

    public static X509Certificate2 CreateSelfSignedCertificate(string subjectName, int keySize)
    {
        using var rsa = RSA.Create(keySize);

        var request = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false)); // serverAuth

        // Modern clients ignore CN and require a SAN.
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(subjectName);

        if (!string.Equals(subjectName, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            sanBuilder.AddDnsName("localhost");
        }

        request.CertificateExtensions.Add(sanBuilder.Build());

        using var selfSigned = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        // Round-tripping through PFX attaches the private key in a form usable by SslStream.
        return X509CertificateLoader.LoadPkcs12(selfSigned.Export(X509ContentType.Pfx), password: null);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _certificate?.Dispose();
            _certificate = null;

            if (_intermediates is { } intermediates)
            {
                foreach (var certificate in intermediates)
                {
                    certificate.Dispose();
                }

                _intermediates = null;
            }
        }
    }
}
