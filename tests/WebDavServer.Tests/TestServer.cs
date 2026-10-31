using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using Strongthium.WebDavServer.Config;
using Strongthium.WebDavServer.Security;

namespace Strongthium.WebDavServer.Tests;

public sealed class FakeClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>The real server, on the loopback address, with a folder of its own that goes when the test does.</summary>
public sealed class TestServer : IAsyncDisposable
{
    public const string Password = "correct horse battery";
    private static readonly Lazy<string> PasswordHash = new(() => Passwords.Hash(Password));

    public static readonly XNamespace D = "DAV:";
    public static readonly XNamespace OC = "http://owncloud.org/ns";

    public string Folder { get; } = Directory.CreateTempSubdirectory("webdav-server-tests-").FullName;
    public FakeClock Clock { get; } = new();
    public ServerApp App { get; private set; } = null!;
    public HttpClient Http { get; } = new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false });
    public string Url { get; private set; } = "";
    public int Port { get; private set; }

    public ServerState State => App.State;

    public static async Task<TestServer> StartAsync(bool tls = false)
    {
        var server = new TestServer();
        var config = new ServerConfig
        {
            Listen = [new ListenerConfig { Address = "127.0.0.1", Port = 0, Tls = tls }],
            Admin = new ListenerConfig { Address = "127.0.0.1", Port = 0 },
        };
        server.App = ServerApp.Build(server.Folder, config, clock: server.Clock);
        await server.App.StartAsync();
        server.Url = server.App.DavAddresses[0];
        server.Port = new Uri(server.Url).Port;
        return server;
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await App.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        for (var tries = 0; tries < 10; tries++)
        {
            try
            {
                Directory.Delete(Folder, recursive: true);
                return;
            }
            catch (IOException)
            {
                await Task.Delay(100);
            }
            catch (UnauthorizedAccessException)
            {
                await Task.Delay(100);
            }
        }
    }

    public void AddMount(MountInfo mount)
    {
        State.Database.SaveMount(mount);
        State.Reload();
    }

    public void AddAccount(string name, params GrantInfo[] grants) => AddAccount(new AccountInfo { Name = name, Grants = [.. grants] });

    public void AddAccount(AccountInfo info)
    {
        State.Database.SaveAccount(info, PasswordHash.Value);
        State.Reload();
    }

    public void ChangeSettings(Func<ServerSettings, ServerSettings> change)
    {
        State.Database.SaveSettings(change(State.Database.LoadSettings()));
        State.Reload();
    }

    public static AuthenticationHeaderValue Basic(string name, string password = Password) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{name}:{password}")));

    /// <summary>A request, as a client would send it. Paths go as they're written: encoding is up to the test.</summary>
    public async Task<HttpResponseMessage> SendAsync(string method, string path, string? user = "alice", string? body = null, string password = Password, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), new Uri(Url + path));
        if (user is not null) request.Headers.Authorization = Basic(user, password);
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, method is "PUT" ? "application/octet-stream" : "application/xml");
        foreach (var (name, value) in headers) request.Headers.TryAddWithoutValidation(name, value);
        return await Http.SendAsync(request);
    }

    public async Task<string> ReadAsync(string path, string user = "alice")
    {
        using var response = await SendAsync("GET", path, user);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync();
    }

    public async Task PutAsync(string path, string content, string user = "alice")
    {
        using var response = await SendAsync("PUT", path, user, content);
        Assert.True(response.IsSuccessStatusCode, $"PUT {path}: {response.StatusCode}");
    }

    public async Task MkcolAsync(string path, string user = "alice")
    {
        using var response = await SendAsync("MKCOL", path, user);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>A PROPFIND's answer, read.</summary>
    public async Task<XElement> PropfindAsync(string path, string depth = "0", string? props = null, string user = "alice")
    {
        var body = props is null ? null : $"""<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns"><d:prop>{props}</d:prop></d:propfind>""";
        using var response = await SendAsync("PROPFIND", path, user, body, Password, ("Depth", depth));
        Assert.Equal((HttpStatusCode)207, response.StatusCode);
        return XElement.Parse(await response.Content.ReadAsStringAsync());
    }

    public static string? Prop(XElement multistatus, XName name, int response = 0) =>
        multistatus.Elements(D + "response").ElementAt(response).Descendants(name).FirstOrDefault()?.Value;

    /// <summary>What a raw socket sees of a request: the bytes that came back, and whether the connection then closed.</summary>
    public async Task<(string Answer, bool Closed)> RawAsync(string request, int port = 0)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port == 0 ? Port : port);
        var stream = client.GetStream();
        var answer = new StringBuilder();
        var closed = false;
        try
        {
            if (request.Length > 0) await stream.WriteAsync(Encoding.ASCII.GetBytes(request));
            var buffer = new byte[4096];
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            while (true)
            {
                var read = await stream.ReadAsync(buffer, timeout.Token);
                if (read == 0)
                {
                    closed = true;
                    break;
                }
                answer.Append(Encoding.ASCII.GetString(buffer, 0, read));
            }
        }
        catch (IOException)
        {
            closed = true;
        }
        catch (SocketException)
        {
            closed = true;
        }
        catch (OperationCanceledException)
        {
            // Still open.
        }
        return (answer.ToString(), closed);
    }

    public static string RawGet(string path, string? user, params string[] headers)
    {
        var text = new StringBuilder($"GET {path} HTTP/1.1\r\nHost: test\r\n");
        if (user is not null) text.Append($"Authorization: {Basic(user)}\r\n");
        foreach (var header in headers) text.Append(header).Append("\r\n");
        return text.Append("\r\n").ToString();
    }
}
