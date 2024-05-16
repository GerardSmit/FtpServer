using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FtpServer;

public class CertificateProvider
{
    private X509Certificate2? _certificate;

    public X509Certificate2 GetCertificate()
    {
        return _certificate ??= CreateSelfSignedCertificate("localhost", 2048);
    }

    public static X509Certificate2 CreateSelfSignedCertificate(string subjectName, int keySize)
    {
        using var rsa = RSA.Create(keySize);
        var request = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var selfSigned = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        return new X509Certificate2(selfSigned.Export(X509ContentType.Pfx));
    }
}
