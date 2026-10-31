using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Strongthium.WebDavServer.Config;

namespace Strongthium.WebDavServer.Network;

/// <summary>
/// The certificate for one listener: the files it's told about, read again when they change so that a renewal takes no restart,
/// or a self-signed one, made the first time and kept in the data folder with its key.
/// </summary>
public sealed class TlsCertificates
{
    private static readonly TimeSpan CheckEvery = TimeSpan.FromMinutes(1);

    private readonly string certificateFile;
    private readonly string keyFile;
    private readonly Lock gate = new();
    private X509Certificate2 current;
    private DateTime loadedStamp;
    private DateTime lastCheck;

    public bool IsSelfSigned { get; }

    public TlsCertificates(string certificateFile, string keyFile, string dataFolder, string name)
    {
        IsSelfSigned = certificateFile.Length == 0;
        if (IsSelfSigned)
        {
            var folder = Path.Combine(dataFolder, "tls");
            Directory.CreateDirectory(folder);
            this.certificateFile = Path.Combine(folder, $"{name}.crt");
            this.keyFile = Path.Combine(folder, $"{name}.key");
            if (!File.Exists(this.certificateFile) || !File.Exists(this.keyFile)) MakeSelfSigned(this.certificateFile, this.keyFile);
        }
        else
        {
            this.certificateFile = certificateFile;
            this.keyFile = keyFile.Length > 0 ? keyFile : certificateFile;
        }
        current = Load();
        loadedStamp = Stamp();
        lastCheck = DateTime.UtcNow;
    }

    /// <summary>The certificate to use now.</summary>
    public X509Certificate2 Current()
    {
        var now = DateTime.UtcNow;
        if (now - lastCheck < CheckEvery) return current;
        lock (gate)
        {
            if (now - lastCheck < CheckEvery) return current;
            lastCheck = now;
            try
            {
                var stamp = Stamp();
                if (stamp != loadedStamp)
                {
                    current = Load();
                    loadedStamp = stamp;
                }
            }
            catch (Exception exception) when (exception is IOException or CryptographicException or UnauthorizedAccessException)
            {
                // A renewal may be halfway through writing. What's there keeps working until the new one can be read.
            }
        }
        return current;
    }

    private DateTime Stamp()
    {
        var a = File.GetLastWriteTimeUtc(certificateFile);
        var b = File.GetLastWriteTimeUtc(keyFile);
        return a > b ? a : b;
    }

    private X509Certificate2 Load()
    {
        using var fromPem = X509Certificate2.CreateFromPemFile(certificateFile, keyFile);
        // Windows' TLS can't use a key that isn't in a store or a PFX: this puts it in the form it wants, on both systems.
        return X509CertificateLoader.LoadPkcs12(fromPem.Export(X509ContentType.Pkcs12), null);
    }

    /// <summary>What the admin window pins, and an admin compares: the SHA-256 of the certificate's public key. Unlike the
    /// certificate's own fingerprint, it stays the same through a renewal that keeps the key.</summary>
    public static string Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));

    private static void MakeSelfSigned(string certificateFile, string keyFile)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var name = Dns.GetHostName();
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(name);
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        names.AddIpAddress(IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        File.WriteAllText(keyFile, key.ExportPkcs8PrivateKeyPem());
        DataFolder.Protect(keyFile);
        File.WriteAllText(certificateFile, certificate.ExportCertificatePem());
    }
}
