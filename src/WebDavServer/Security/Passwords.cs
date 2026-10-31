using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Strongthium.WebDavServer.Security;

/// <summary>
/// Passwords are kept only as Argon2id hashes (RFC 9106), in the usual <c>$argon2id$v=19$m=…,t=…,p=…$salt$hash</c> form. App
/// passwords are random and long enough that guessing isn't possible, so a plain SHA-256 of them is kept, and checking one
/// takes no time at all, which matters since WebDAV logs in on every request.
/// </summary>
public static class Passwords
{
    // 64 MiB and three passes: stronger than OWASP's minimum (19 MiB and two), and about a quarter of a second on a server.
    private const int MemoryKib = 64 * 1024, Passes = 3, Lanes = 2, SaltBytes = 16, HashBytes = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Compute(password, salt, MemoryKib, Passes, Lanes, HashBytes);
        return $"$argon2id$v=19$m={MemoryKib},t={Passes},p={Lanes}${Convert.ToBase64String(salt).TrimEnd('=')}${Convert.ToBase64String(hash).TrimEnd('=')}";
    }

    public static bool Verify(string password, string encoded)
    {
        var parts = encoded.Split('$');
        if (parts is not ["", "argon2id", "v=19", var costs, var saltText, var hashText]) return false;
        int memory = 0, passes = 0, lanes = 0;
        foreach (var cost in costs.Split(','))
        {
            if (cost.Length < 3 || !int.TryParse(cost.AsSpan(2), out var value)) return false;
            switch (cost[0])
            {
                case 'm': memory = value; break;
                case 't': passes = value; break;
                case 'p': lanes = value; break;
            }
        }
        // What's stored is the server's own, but a damaged row shouldn't take the server's memory with it.
        if (memory is < 8 or > 4 * 1024 * 1024 || passes is < 1 or > 64 || lanes is < 1 or > 64) return false;
        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(Pad(saltText));
            expected = Convert.FromBase64String(Pad(hashText));
        }
        catch (FormatException)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(Compute(password, salt, memory, passes, lanes, expected.Length), expected);
    }

    /// <summary>A hash nobody's password matches, to check against when the account doesn't exist, so that a wrong name
    /// takes as long as a wrong password.</summary>
    public static readonly Lazy<string> Decoy = new(() => Hash(Convert.ToHexString(RandomNumberGenerator.GetBytes(32))));

    public static byte[] Compute(string password, byte[] salt, int memoryKib, int passes, int lanes, int length)
    {
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = passes,
            DegreeOfParallelism = lanes,
        };
        return argon.GetBytes(length);
    }

    private static string Pad(string base64) => base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');

    // ---- App passwords ---------------------------------------------------------------------------------------------

    private const string AppAlphabet = "abcdefghjkmnpqrstuvwxyz23456789";
    private const int AppGroups = 6, AppGroupLength = 6;

    /// <summary>A new app password: six groups of six from 31 characters, 178 bits, which can be read out and typed.</summary>
    public static string NewAppPassword()
    {
        var text = new StringBuilder(AppGroups * (AppGroupLength + 1));
        for (var group = 0; group < AppGroups; group++)
        {
            if (group > 0) text.Append('-');
            for (var i = 0; i < AppGroupLength; i++) text.Append(AppAlphabet[RandomNumberGenerator.GetInt32(AppAlphabet.Length)]);
        }
        return text.ToString();
    }

    /// <summary>Whether a password has the form of an app password, and so is checked as one.</summary>
    public static bool LooksLikeAppPassword(string password)
    {
        if (password.Length != AppGroups * (AppGroupLength + 1) - 1) return false;
        for (var i = 0; i < password.Length; i++)
        {
            if ((i + 1) % (AppGroupLength + 1) == 0)
            {
                if (password[i] != '-') return false;
            }
            else if (!AppAlphabet.Contains(password[i])) return false;
        }
        return true;
    }

    public static string HashAppPassword(string password) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
}
