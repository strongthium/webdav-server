using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Strongthium.WebDavServer.Storage;

/// <summary>An account as the database has it.</summary>
public sealed record AccountRow(AccountInfo Info, string PasswordHash, long CredentialGeneration);

public sealed record AppPasswordRow(long Id, string Account, string Name, string TokenHash, DateTimeOffset Created, DateTimeOffset? LastUsed);

public sealed record AdminRow(string Name, string PasswordHash, bool MustChange, long Generation);

/// <summary>
/// The server's state, in one SQLite file: accounts, paths, settings, bans, the log, and what's known of files beyond what
/// the file system keeps (their ids, how often they've changed, their properties). Every value goes in by parameter.
/// </summary>
public sealed class Database
{
    private readonly string connectionString;

    public Database(string file)
    {
        connectionString = new SqliteConnectionStringBuilder { DataSource = file, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = true, DefaultTimeout = 30 }.ToString();
        var isNew = !File.Exists(file);
        using (var connection = Open())
        {
            Run(connection, "PRAGMA journal_mode=WAL;");
            Run(connection, """
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS admins (name TEXT PRIMARY KEY COLLATE NOCASE, password_hash TEXT NOT NULL, must_change INTEGER NOT NULL, generation INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS mounts (path TEXT PRIMARY KEY, json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS accounts (name TEXT PRIMARY KEY, json TEXT NOT NULL, password_hash TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS app_passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created TEXT NOT NULL, last_used TEXT);
                CREATE INDEX IF NOT EXISTS app_passwords_account ON app_passwords (account);
                CREATE TABLE IF NOT EXISTS bans (network TEXT NOT NULL, scope TEXT NOT NULL, reason TEXT NOT NULL, created TEXT NOT NULL, until TEXT, PRIMARY KEY (network, scope));
                CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, kind TEXT NOT NULL, address TEXT NOT NULL, account TEXT NOT NULL, scope TEXT NOT NULL, message TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, space TEXT NOT NULL, path TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1, UNIQUE (space, path));
                CREATE TABLE IF NOT EXISTS node_props (node INTEGER NOT NULL REFERENCES nodes (id) ON DELETE CASCADE, ns TEXT NOT NULL, name TEXT NOT NULL, xml TEXT NOT NULL, PRIMARY KEY (node, ns, name));
                """);
        }
        if (isNew) Config.DataFolder.Protect(file);
    }

    public SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        Run(connection, "PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;");
        return connection;
    }

    private static void Run(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    internal static SqliteCommand Command(SqliteConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }

    private int Execute(string sql, params (string Name, object? Value)[] parameters)
    {
        using var connection = Open();
        using var command = Command(connection, sql, parameters);
        return command.ExecuteNonQuery();
    }

    private static string Time(DateTimeOffset time) => time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static DateTimeOffset ReadTime(string text) => DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

    // ---- Settings ------------------------------------------------------------------------------------------------

    public ServerSettings LoadSettings()
    {
        using var connection = Open();
        using var command = Command(connection, "SELECT value FROM settings WHERE key = 'server'");
        return command.ExecuteScalar() is string json ? JsonSerializer.Deserialize<ServerSettings>(json, Api.Json) ?? new ServerSettings() : new ServerSettings();
    }

    public void SaveSettings(ServerSettings settings) =>
        Execute("INSERT INTO settings (key, value) VALUES ('server', @value) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            ("@value", JsonSerializer.Serialize(settings, Api.Json)));

    // ---- Admin ---------------------------------------------------------------------------------------------------

    public AdminRow? LoadAdmin()
    {
        using var connection = Open();
        using var command = Command(connection, "SELECT name, password_hash, must_change, generation FROM admins LIMIT 1");
        using var reader = command.ExecuteReader();
        return reader.Read() ? new AdminRow(reader.GetString(0), reader.GetString(1), reader.GetInt64(2) != 0, reader.GetInt64(3)) : null;
    }

    public void SaveAdmin(string name, string passwordHash, bool mustChange)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        long generation;
        using (var read = Command(connection, "SELECT COALESCE(MAX(generation), 0) FROM admins")) generation = (long)read.ExecuteScalar()! + 1;
        using (var delete = Command(connection, "DELETE FROM admins")) delete.ExecuteNonQuery();
        using (var insert = Command(connection, "INSERT INTO admins (name, password_hash, must_change, generation) VALUES (@name, @hash, @must, @generation)",
            ("@name", name), ("@hash", passwordHash), ("@must", mustChange ? 1 : 0), ("@generation", generation))) insert.ExecuteNonQuery();
        transaction.Commit();
    }

    // ---- Paths ---------------------------------------------------------------------------------------------------

    public List<MountInfo> LoadMounts()
    {
        var mounts = new List<MountInfo>();
        using var connection = Open();
        using var command = Command(connection, "SELECT json FROM mounts ORDER BY path");
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (JsonSerializer.Deserialize<MountInfo>(reader.GetString(0), Api.Json) is { } mount) mounts.Add(mount);
        }
        return mounts;
    }

    public void SaveMount(MountInfo mount) =>
        Execute("INSERT INTO mounts (path, json) VALUES (@path, @json) ON CONFLICT (path) DO UPDATE SET json = excluded.json",
            ("@path", mount.Path), ("@json", JsonSerializer.Serialize(mount, Api.Json)));

    public bool DeleteMount(string path) => Execute("DELETE FROM mounts WHERE path = @path", ("@path", path)) > 0;

    // ---- Accounts ------------------------------------------------------------------------------------------------

    public List<AccountRow> LoadAccounts()
    {
        var accounts = new List<AccountRow>();
        using var connection = Open();
        using var command = Command(connection, "SELECT json, password_hash, generation FROM accounts ORDER BY name");
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            if (JsonSerializer.Deserialize<AccountInfo>(reader.GetString(0), Api.Json) is { } info) accounts.Add(new AccountRow(info, reader.GetString(1), reader.GetInt64(2)));
        }
        return accounts;
    }

    /// <summary>Saves an account. A password hash of null leaves the one it has; an empty one takes it away.</summary>
    public void SaveAccount(AccountInfo info, string? passwordHash)
    {
        using var connection = Open();
        using var command = Command(connection, """
            INSERT INTO accounts (name, json, password_hash) VALUES (@name, @json, COALESCE(@hash, ''))
            ON CONFLICT (name) DO UPDATE SET json = excluded.json,
                password_hash = COALESCE(@hash, accounts.password_hash),
                generation = accounts.generation + 1
            """, ("@name", info.Name), ("@json", JsonSerializer.Serialize(info with { AppPasswords = [], UsedBytes = -1, HasPassword = false }, Api.Json)), ("@hash", passwordHash));
        command.ExecuteNonQuery();
    }

    public bool DeleteAccount(string name)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var tokens = Command(connection, "DELETE FROM app_passwords WHERE account = @name", ("@name", name))) tokens.ExecuteNonQuery();
        int deleted;
        using (var account = Command(connection, "DELETE FROM accounts WHERE name = @name", ("@name", name))) deleted = account.ExecuteNonQuery();
        transaction.Commit();
        return deleted > 0;
    }

    public List<AppPasswordRow> LoadAppPasswords()
    {
        var rows = new List<AppPasswordRow>();
        using var connection = Open();
        using var command = Command(connection, "SELECT id, account, name, token_hash, created, last_used FROM app_passwords ORDER BY id");
        using var reader = command.ExecuteReader();
        while (reader.Read())
            rows.Add(new AppPasswordRow(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), ReadTime(reader.GetString(4)), reader.IsDBNull(5) ? null : ReadTime(reader.GetString(5))));
        return rows;
    }

    public long AddAppPassword(string account, string name, string tokenHash, DateTimeOffset created)
    {
        using var connection = Open();
        using var command = Command(connection, "INSERT INTO app_passwords (account, name, token_hash, created) VALUES (@account, @name, @hash, @created) RETURNING id",
            ("@account", account), ("@name", name), ("@hash", tokenHash), ("@created", Time(created)));
        return (long)command.ExecuteScalar()!;
    }

    public bool DeleteAppPassword(string account, long id) =>
        Execute("DELETE FROM app_passwords WHERE id = @id AND account = @account", ("@id", id), ("@account", account)) > 0;

    public void TouchAppPassword(long id, DateTimeOffset time) =>
        Execute("UPDATE app_passwords SET last_used = @time WHERE id = @id", ("@id", id), ("@time", Time(time)));

    // ---- Bans ----------------------------------------------------------------------------------------------------

    public List<BanInfo> LoadBans()
    {
        var bans = new List<BanInfo>();
        using var connection = Open();
        using var command = Command(connection, "SELECT network, scope, reason, created, until FROM bans");
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            bans.Add(new BanInfo
            {
                Network = reader.GetString(0),
                Scope = reader.GetString(1),
                Reason = reader.GetString(2),
                Created = ReadTime(reader.GetString(3)),
                Until = reader.IsDBNull(4) ? null : ReadTime(reader.GetString(4)),
            });
        }
        return bans;
    }

    public void SaveBan(BanInfo ban) =>
        Execute("""
            INSERT INTO bans (network, scope, reason, created, until) VALUES (@network, @scope, @reason, @created, @until)
            ON CONFLICT (network, scope) DO UPDATE SET reason = excluded.reason, created = excluded.created, until = excluded.until
            """, ("@network", ban.Network), ("@scope", ban.Scope), ("@reason", ban.Reason), ("@created", Time(ban.Created)), ("@until", ban.Until is { } until ? Time(until) : null));

    public bool DeleteBan(string network, string scope) =>
        Execute("DELETE FROM bans WHERE network = @network AND scope = @scope", ("@network", network), ("@scope", scope)) > 0;

    public void DeleteBansOfScope(string scope) => Execute("DELETE FROM bans WHERE scope = @scope", ("@scope", scope));

    public void DeleteExpiredBans(DateTimeOffset now) => Execute("DELETE FROM bans WHERE until IS NOT NULL AND until <= @now", ("@now", Time(now)));

    // ---- The log -------------------------------------------------------------------------------------------------

    public void AddLog(DateTimeOffset time, string kind, string address, string account, string scope, string message) =>
        Execute("INSERT INTO log (time, kind, address, account, scope, message) VALUES (@time, @kind, @address, @account, @scope, @message)",
            ("@time", Time(time)), ("@kind", kind), ("@address", address), ("@account", account), ("@scope", scope), ("@message", message));

    public List<LogEntry> ReadLog(int limit, string? kind)
    {
        var entries = new List<LogEntry>();
        using var connection = Open();
        using var command = Command(connection, """
            SELECT id, time, kind, address, account, scope, message FROM log
            WHERE @kind IS NULL OR kind = @kind ORDER BY id DESC LIMIT @limit
            """, ("@kind", kind), ("@limit", Math.Clamp(limit, 1, 5000)));
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            entries.Add(new LogEntry
            {
                Id = reader.GetInt64(0),
                Time = ReadTime(reader.GetString(1)),
                Kind = reader.GetString(2),
                Address = reader.GetString(3),
                Account = reader.GetString(4),
                Scope = reader.GetString(5),
                Message = reader.GetString(6),
            });
        }
        return entries;
    }

    /// <summary>The log keeps 90 days, and at most 200,000 lines.</summary>
    public void TrimLog(DateTimeOffset before)
    {
        Execute("DELETE FROM log WHERE time < @before", ("@before", Time(before)));
        Execute("DELETE FROM log WHERE id <= (SELECT MAX(id) FROM log) - 200000");
    }
}
