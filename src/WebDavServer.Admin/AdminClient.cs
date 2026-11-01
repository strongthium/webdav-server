using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Strongthium.WebDavServer.AdminApp;

/// <summary>Something the server said no to, in the server's own words.</summary>
public sealed class ApiException(string message, string code, HttpStatusCode status) : Exception(message)
{
    public string Code { get; } = code;
    public HttpStatusCode Status { get; } = status;
}

/// <summary>The server's certificate isn't the one that was trusted, or none has been yet: nothing has been sent.</summary>
public sealed class UntrustedCertificateException(string presented, string? trusted) : Exception("The server's certificate isn't the one trusted.")
{
    public string Presented { get; } = presented;
    public string? Trusted { get; } = trusted;
}

/// <summary>
/// The connection to a server's admin port. It's TLS with the server's own certificate, which no authority vouches for, so
/// instead of asking who signed it, this holds on to the certificate's key once the admin has compared it with what the server
/// shows, and refuses anything else. A password goes nowhere until that's done. The token the server gives back is kept in
/// memory, and never saved.
/// </summary>
public sealed class AdminClient : IDisposable
{
    private readonly HttpClient http;
    private readonly string? trusted;
    private string? presented;

    public string Address { get; }

    public AdminClient(string host, int port, string? trustedFingerprint)
    {
        trusted = trustedFingerprint;
        Address = host.Contains(':') && !host.StartsWith('[') ? $"https://[{host}]:{port}" : $"https://{host}:{port}";
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };
        handler.SslOptions.RemoteCertificateValidationCallback = Validate;
        http = new HttpClient(handler) { BaseAddress = new Uri(Address), Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"webdav-server-admin/{Updater.RunningVersion.ToString(4)}");
    }

    private bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null) return false;
        using var parsed = new X509Certificate2(certificate);
        presented = Convert.ToHexString(SHA256.HashData(parsed.PublicKey.ExportSubjectPublicKeyInfo()));
        return trusted is not null && presented.Equals(trusted, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose() => http.Dispose();

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string address, object? body)
    {
        using var request = new HttpRequestMessage(method, address);
        if (body is not null) request.Content = JsonContent.Create(body, body.GetType(), options: Api.Json);
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request);
        }
        catch (HttpRequestException) when (presented is not null && !presented.Equals(trusted, StringComparison.OrdinalIgnoreCase))
        {
            throw new UntrustedCertificateException(presented, trusted);
        }
        if (response.IsSuccessStatusCode) return response;
        using (response)
        {
            ApiError? error = null;
            try
            {
                error = await response.Content.ReadFromJsonAsync<ApiError>(Api.Json);
            }
            catch (Exception exception) when (exception is JsonException or NotSupportedException or InvalidOperationException)
            {
                // Not what the server says: something else is on that port.
            }
            if (response.StatusCode == HttpStatusCode.Unauthorized && request.RequestUri?.OriginalString != "/api/login") SessionEnded?.Invoke();
            throw new ApiException(error?.Error is { Length: > 0 } said ? said : $"The server answered {(int)response.StatusCode}.", error?.Code ?? "", response.StatusCode);
        }
    }

    /// <summary>Said when the server has stopped knowing this session: the login has timed out.</summary>
    public event Action? SessionEnded;

    public async Task<T> GetAsync<T>(string address)
    {
        using var response = await SendAsync(HttpMethod.Get, address, null);
        return await response.Content.ReadFromJsonAsync<T>(Api.Json) ?? throw new InvalidDataException("The server's answer couldn't be read.");
    }

    public async Task<T> PostAsync<T>(string address, object body)
    {
        using var response = await SendAsync(HttpMethod.Post, address, body);
        return await response.Content.ReadFromJsonAsync<T>(Api.Json) ?? throw new InvalidDataException("The server's answer couldn't be read.");
    }

    public async Task PostAsync(string address, object? body = null)
    {
        using var response = await SendAsync(HttpMethod.Post, address, body);
    }

    public async Task PutAsync(string address, object body)
    {
        using var response = await SendAsync(HttpMethod.Put, address, body);
    }

    public async Task DeleteAsync(string address)
    {
        using var response = await SendAsync(HttpMethod.Delete, address, null);
    }

    public async Task<LoginResponse> LoginAsync(string userName, string password)
    {
        var answer = await PostAsync<LoginResponse>("/api/login", new LoginRequest { UserName = userName, Password = password });
        UseToken(answer.Token);
        return answer;
    }

    public async Task<LoginResponse> ChangePasswordAsync(string current, string next, string newUserName)
    {
        var answer = await PostAsync<LoginResponse>("/api/password", new ChangePasswordRequest { CurrentPassword = current, NewPassword = next, NewUserName = newUserName });
        UseToken(answer.Token);
        return answer;
    }

    private void UseToken(string token) => http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

    /// <summary>A query string's value.</summary>
    public static string Q(string value) => Uri.EscapeDataString(value);

    /// <summary>A sentence about anything that can go wrong in talking to the server.</summary>
    public static string Explain(Exception exception) => exception switch
    {
        ApiException api => api.Message,
        HttpRequestException { InnerException: System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.ConnectionRefused } } =>
            "Nothing is listening at that address and port. Is the server running?",
        HttpRequestException { InnerException: System.Net.Sockets.SocketException } network => network.InnerException!.Message,
        HttpRequestException =>
            "The server closed the connection without answering. This address may be banned, or outside the admin whitelist. On the server, webdav-server --unban ADDRESS lets it back in.",
        TaskCanceledException => "The server took too long to answer.",
        _ => exception.Message,
    };

    public static bool IsExpected(Exception exception) =>
        exception is ApiException or HttpRequestException or TaskCanceledException or InvalidDataException or JsonException or IOException;
}

/// <summary>A server this PC has connected to: where it is, and the certificate it was trusted with. Never a password.</summary>
public sealed record ServerProfile
{
    public string Host { get; init; } = "localhost";
    public int Port { get; init; } = 9443;
    public string UserName { get; init; } = "admin";
    public string? Fingerprint { get; init; }
    public override string ToString() => Port == 9443 ? Host : $"{Host}:{Port}";
}

public static class Profiles
{
    private static string File_ => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Strongthium", "webdav-server-admin", "servers.json");

    public static List<ServerProfile> Load()
    {
        try
        {
            return File.Exists(File_) ? JsonSerializer.Deserialize<List<ServerProfile>>(File.ReadAllText(File_), Api.Json) ?? [] : [];
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>Remembers a server, most recent first.</summary>
    public static void Remember(ServerProfile profile)
    {
        var profiles = Load();
        profiles.RemoveAll(other => other.Host.Equals(profile.Host, StringComparison.OrdinalIgnoreCase) && other.Port == profile.Port);
        profiles.Insert(0, profile);
        Directory.CreateDirectory(Path.GetDirectoryName(File_)!);
        File.WriteAllText(File_, JsonSerializer.Serialize(profiles, Api.Json));
    }
}

/// <summary>The server the window is connected to.</summary>
public static class Session
{
    public static AdminClient Client { get; set; } = null!;
    public static string UserName { get; set; } = "";
    public static ServerProfile Profile { get; set; } = new();
}
