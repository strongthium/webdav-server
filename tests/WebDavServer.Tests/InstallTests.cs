using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Strongthium.WebDavServer.Install;

namespace Strongthium.WebDavServer.Tests;

/// <summary>What <c>--install</c> asks and writes. Installing itself changes the machine, so it isn't run here: the parts
/// that decide what goes where are, and the program's own refusal to install from dotnet is in <see cref="ProgramTests"/>.</summary>
public sealed class InstallTests : IDisposable
{
    private readonly string folder = Directory.CreateTempSubdirectory("webdav-server-install-").FullName;

    public void Dispose() => Directory.Delete(folder, recursive: true);

    /// <summary>Answers questions from a list, the way someone at the terminal would, then nothing, as at the end of input.</summary>
    private static Func<string, string?> Answers(List<string> asked, params string[] answers)
    {
        var queue = new Queue<string>(answers);
        return question =>
        {
            asked.Add(question);
            return queue.TryDequeue(out var answer) ? answer : null;
        };
    }

    private string WriteCertificate(string name, DateTimeOffset from, DateTimeOffset until, bool keyInSameFile = false)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=files.example.com", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("files.example.com");
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(from, until);
        var path = Path.Combine(folder, $"{name}.pem");
        File.WriteAllText(path, certificate.ExportCertificatePem() + "\n" + (keyInSameFile ? key.ExportPkcs8PrivateKeyPem() : ""));
        if (!keyInSameFile) File.WriteAllText(Path.Combine(folder, $"{name}.key"), key.ExportPkcs8PrivateKeyPem());
        return path;
    }

    [Fact]
    public void APortInUseIsPassedOver()
    {
        using var listener = TcpListener.Create(0);
        listener.Start();
        var taken = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        Assert.False(Installer.IsFree(taken));
        var found = Installer.FreePort([taken]);
        Assert.True(found > taken);
        Assert.True(Installer.IsFree(found));
        Assert.NotEqual(found, Installer.FreePort([found], not: found));
    }

    [Fact]
    public void WithNoAnswersItTakesTheSuggestions()
    {
        var asked = new List<string>();
        var config = Installer.Ask(Answers(asked), _ => { });
        var listener = Assert.Single(config.Listen);
        Assert.True(listener.Tls);
        Assert.Equal("*", listener.Address);
        Assert.NotEqual(listener.Port, config.Admin.Port);
        Assert.True(Installer.IsFree(listener.Port));
        Assert.True(Installer.IsFree(config.Admin.Port));
        Assert.Equal("", config.CertificateFile);
        Assert.Equal("", config.KeyFile);
        Assert.Equal(3, asked.Count);
    }

    [Fact]
    public void ItAsksAgainAboutWhatWontWork()
    {
        using var listener = TcpListener.Create(0);
        listener.Start();
        var taken = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var said = new List<string>();
        var asked = new List<string>();
        var suggestedDav = Installer.FreePort([443, 8443]);

        var config = Installer.Ask(Answers(asked, "lots", "70000", taken.ToString(), "", suggestedDav.ToString(), "", Path.Combine(folder, "missing.pem"), "", ""), said.Add);

        Assert.Contains(said, line => line.Contains("1 to 65535"));
        Assert.Contains(said, line => line.Contains($"already using port {taken}"));
        Assert.Contains(said, line => line.Contains("needs a port of its own"));
        Assert.Contains(said, line => line.Contains("missing.pem"));
        Assert.Equal(suggestedDav, Assert.Single(config.Listen).Port);
        Assert.NotEqual(suggestedDav, config.Admin.Port);
        Assert.Equal("", config.CertificateFile);
    }

    [Fact]
    public void ItTakesACertificateAndItsKey()
    {
        var certificate = WriteCertificate("files", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        var said = new List<string>();
        var config = Installer.Ask(Answers([], "", "", $"\"{certificate}\"", Path.ChangeExtension(certificate, ".key")), said.Add);
        Assert.Equal(certificate, config.CertificateFile);
        Assert.Equal(Path.ChangeExtension(certificate, ".key"), config.KeyFile);
        Assert.Contains(said, line => line.Contains("files.example.com, good until"));
    }

    [Fact]
    public void TheKeyCanBeInTheCertificatesFile()
    {
        var both = WriteCertificate("both", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90), keyInSameFile: true);
        var config = Installer.Ask(Answers([], "", "", both, ""), _ => { });
        Assert.Equal(both, config.CertificateFile);
        Assert.Equal("", config.KeyFile);
    }

    [Fact]
    public void ItTurnsDownCertificatesThatWontDo()
    {
        var expired = WriteCertificate("old", DateTimeOffset.UtcNow.AddDays(-100), DateTimeOffset.UtcNow.AddDays(-1));
        Assert.Contains("ran out", Installer.CertificateProblem(expired, Path.ChangeExtension(expired, ".key"), out _));

        // A certificate with no key, and a key that isn't the certificate's.
        Assert.Contains("isn't a PEM certificate", Installer.CertificateProblem(expired, "", out _));
        var other = WriteCertificate("other", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        Assert.Contains("isn't a PEM certificate", Installer.CertificateProblem(other, Path.ChangeExtension(expired, ".key"), out _));

        // The service's account has to be able to read it, too.
        var said = new List<string>();
        var config = Installer.Ask(Answers([], "", "", other, Path.ChangeExtension(other, ".key"), ""), said.Add, file => $"can't read {file}");
        Assert.Contains(said, line => line == $"can't read {other}");
        Assert.Equal("", config.CertificateFile);
    }

    [Fact]
    public void TheUnitIsTheOneInDeploy()
    {
        var unit = Installer.SystemdUnit(Installer.UnitTemplate(), Installer.LinuxDefaultData, lowPort: false, "/usr/lib/dotnet", []);
        Assert.StartsWith("# Written by webdav-server --install", unit);
        Assert.DoesNotContain("useradd", unit);
        Assert.Contains("\nExecStart=/usr/local/bin/webdav-server\nEnvironment=DOTNET_ROOT=/usr/lib/dotnet\n", unit);
        Assert.Contains("\nStateDirectory=webdav-server\n", unit);
        Assert.Contains("\nWorkingDirectory=/var/lib/webdav-server\n", unit);
        Assert.Contains("\n#AmbientCapabilities=CAP_NET_BIND_SERVICE\n", unit);
        Assert.Contains("\n#ReadWritePaths=/srv/team\n", unit);
        Assert.Contains("\nProtectSystem=strict\n", unit);
        Assert.Contains("\nWantedBy=multi-user.target\n", unit);
    }

    [Fact]
    public void ADataFolderOfItsOwnAndALowPort()
    {
        var unit = Installer.SystemdUnit(Installer.UnitTemplate(), "/srv/webdav", lowPort: true, dotnetRoot: null, ["ReadWritePaths=/srv/team", "ReadWritePaths=/srv/webdav"]);
        Assert.Contains("\nExecStart=/usr/local/bin/webdav-server --data /srv/webdav\nRestart=", unit);
        Assert.DoesNotContain("StateDirectory", unit);
        Assert.DoesNotContain("DOTNET_ROOT", unit);
        Assert.Contains("\nWorkingDirectory=/srv/webdav\n", unit);
        Assert.Contains("\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n", unit);
        Assert.Single(unit.Split('\n'), line => line == "ReadWritePaths=/srv/webdav");
        Assert.Contains("\nReadWritePaths=/srv/team\n", unit);
        Assert.DoesNotContain("#ReadWritePaths", unit);

        // What an admin allowed by hand stays allowed when it's installed again.
        var again = Installer.SystemdUnit(Installer.UnitTemplate(), Installer.LinuxDefaultData, lowPort: false, null, ["AmbientCapabilities=CAP_NET_BIND_SERVICE"]);
        Assert.Contains("\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n", again);
    }

    [Theory]
    [InlineData("/srv/webdav", true)]
    [InlineData("/var/lib/webdav-server", true)]
    [InlineData("/home/alice/webdav", false)]
    [InlineData("/root", false)]
    [InlineData("/srv/my files", false)]
    [InlineData("/srv/100%", false)]
    public void PathsTheServiceCanUse(string path, bool fine) => Assert.Equal(fine, Installer.LinuxPathProblem(path) is null);
}
