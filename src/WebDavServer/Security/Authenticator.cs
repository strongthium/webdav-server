using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Strongthium.WebDavServer.Security;

public enum LoginVerdict
{
    Accepted,

    /// <summary>Wrong name or password. It's counted against the address.</summary>
    Refused,

    /// <summary>Too many logins being checked at once: nothing is known yet, so nothing is counted.</summary>
    Busy,
}

public sealed record LoginResult(LoginVerdict Verdict, Account? Account = null, long? AppPasswordId = null);

/// <summary>
/// Checks a name and password. WebDAV sends them with every request, and Argon2 is slow by design, so a password that has been
/// checked is remembered for a few minutes, as a keyed hash under a key that only ever exists in this process's memory. A
/// password change makes what's remembered useless, since the account's generation goes into the hash.
/// </summary>
public sealed class Authenticator
{
    private static readonly TimeSpan RememberFor = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan AppPasswordTouchEvery = TimeSpan.FromHours(1);
    private const int MaxWaiting = 64;

    private readonly ServerState state;
    private readonly byte[] cacheKey = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, (byte[] Mac, DateTimeOffset Until)> remembered = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<long, DateTimeOffset> touched = new();
    private readonly SemaphoreSlim hashing = new(Math.Max(2, Environment.ProcessorCount / 2));
    private int waiting;

    public Authenticator(ServerState state) => this.state = state;

    public async Task<LoginResult> CheckAsync(string name, string password, CancellationToken cancel)
    {
        var policy = state.Policy;
        policy.Accounts.TryGetValue(name, out var account);
        if (account is { Info.Enabled: false }) account = null;

        // App passwords have a form of their own, and hold enough randomness that no slow hash is called for.
        // A guess in that form is refused just as fast for a name that doesn't exist, so it can't tell which names do.
        if (Passwords.LooksLikeAppPassword(password))
        {
            if (account is not null && account.AppPasswords.TryGetValue(Passwords.HashAppPassword(password), out var id))
            {
                Touch(id);
                return new LoginResult(LoginVerdict.Accepted, account, id);
            }
            return new LoginResult(LoginVerdict.Refused);
        }

        if (account is { Info.RequireAppPasswords: true } or { PasswordHash.Length: 0 }) account = null;
        var hash = account?.PasswordHash ?? Passwords.Decoy.Value;
        if (account is not null && IsRemembered(account, password)) return new LoginResult(LoginVerdict.Accepted, account);

        var verdict = await SlowVerifyAsync(password, hash, cancel);
        if (verdict == LoginVerdict.Busy) return new LoginResult(LoginVerdict.Busy);
        if (verdict != LoginVerdict.Accepted || account is null) return new LoginResult(LoginVerdict.Refused);
        Remember(account, password);
        return new LoginResult(LoginVerdict.Accepted, account);
    }

    /// <summary>Checks a password against a hash, with a limit on how many run at once. One wrong password costs the server
    /// 64 MiB and a quarter of a second, so without this a burst of them from many places could be an attack on the server's
    /// memory. Past the limit, requests are told to come back.</summary>
    public async Task<LoginVerdict> SlowVerifyAsync(string password, string hash, CancellationToken cancel)
    {
        if (Interlocked.Increment(ref waiting) > MaxWaiting)
        {
            Interlocked.Decrement(ref waiting);
            return LoginVerdict.Busy;
        }
        try
        {
            await hashing.WaitAsync(cancel);
            try
            {
                return await Task.Run(() => Passwords.Verify(password, hash), cancel) ? LoginVerdict.Accepted : LoginVerdict.Refused;
            }
            finally
            {
                hashing.Release();
            }
        }
        finally
        {
            Interlocked.Decrement(ref waiting);
        }
    }

    private byte[] Mac(Account account, string password) =>
        HMACSHA256.HashData(cacheKey, Encoding.UTF8.GetBytes($"{account.Generation}\n{account.PasswordHash}\n{password}"));

    private bool IsRemembered(Account account, string password)
    {
        if (!remembered.TryGetValue(account.Name, out var entry)) return false;
        if (entry.Until <= state.Clock.GetUtcNow())
        {
            remembered.TryRemove(account.Name, out _);
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(entry.Mac, Mac(account, password));
    }

    private void Remember(Account account, string password) =>
        remembered[account.Name] = (Mac(account, password), state.Clock.GetUtcNow() + RememberFor);

    private void Touch(long id)
    {
        var now = state.Clock.GetUtcNow();
        if (touched.TryGetValue(id, out var last) && now - last < AppPasswordTouchEvery) return;
        touched[id] = now;
        state.Database.TouchAppPassword(id, now);
    }

    public void Forget(string name) => remembered.TryRemove(name, out _);
}

/// <summary>A <c>Basic</c> Authorization header, read.</summary>
public static class BasicAuth
{
    public static bool TryParse(string header, out string name, out string password)
    {
        name = password = "";
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase) || header.Length > 8192) return false;
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(header[6..].Trim());
        }
        catch (FormatException)
        {
            return false;
        }
        string text;
        try
        {
            text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            // Older clients send Latin-1, which any bytes are.
            text = Encoding.Latin1.GetString(bytes);
        }
        var colon = text.IndexOf(':');
        if (colon <= 0) return false;
        name = text[..colon].Trim();
        password = text[(colon + 1)..];
        return name.Length is > 0 and <= 256 && !name.Any(char.IsControl) && password.Length <= 1024;
    }
}
