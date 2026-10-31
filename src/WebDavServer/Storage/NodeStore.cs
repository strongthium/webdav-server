using Microsoft.Data.Sqlite;

namespace Strongthium.WebDavServer.Storage;

/// <summary>What's known of a file or folder beyond what the file system says.</summary>
public readonly record struct Node(long Id, long Generation);

/// <summary>
/// A file or folder's id, which stays with it through a move, its generation, which goes up with every change to it and, for
/// a folder, to anything inside it, and its properties. Sync clients find what's changed by walking down from the top through
/// the folders whose tag has changed, so a change has to show on every folder above it. Rows are made when first asked for.
/// </summary>
public sealed class NodeStore(Database database)
{
    /// <summary>Keys are as the file system compares names: Windows' don't care about case.</summary>
    private static string Key(string path) => OperatingSystem.IsWindows() ? path.ToLowerInvariant() : path;

    public Node Get(string space, string path) => GetMany(space, [path])[0];

    /// <summary>The rows for many paths at once, in one transaction, as a folder listing needs.</summary>
    public Node[] GetMany(string space, IReadOnlyList<string> paths)
    {
        var nodes = new Node[paths.Count];
        using var connection = database.Open();
        var missing = new List<int>();
        using (var select = Database.Command(connection, "SELECT id, generation FROM nodes WHERE space = @space AND path = @path", ("@space", space), ("@path", "")))
        {
            for (var i = 0; i < paths.Count; i++)
            {
                select.Parameters["@path"].Value = Key(paths[i]);
                using var reader = select.ExecuteReader();
                if (reader.Read()) nodes[i] = new Node(reader.GetInt64(0), reader.GetInt64(1));
                else missing.Add(i);
            }
        }
        if (missing.Count == 0) return nodes;

        using var transaction = connection.BeginTransaction();
        using var insert = Database.Command(connection, """
            INSERT INTO nodes (space, path) VALUES (@space, @path)
            ON CONFLICT (space, path) DO UPDATE SET generation = nodes.generation
            RETURNING id, generation
            """, ("@space", space), ("@path", ""));
        foreach (var i in missing)
        {
            insert.Parameters["@path"].Value = Key(paths[i]);
            using var reader = insert.ExecuteReader();
            reader.Read();
            nodes[i] = new Node(reader.GetInt64(0), reader.GetInt64(1));
        }
        transaction.Commit();
        return nodes;
    }

    /// <summary>Marks a path changed, and every folder above it up to the top of the space.</summary>
    public void Changed(string space, string path)
    {
        using var connection = database.Open();
        using var transaction = connection.BeginTransaction();
        ChangedIn(connection, space, Key(path));
        transaction.Commit();
    }

    private static void ChangedIn(SqliteConnection connection, string space, string key)
    {
        using var upsert = Database.Command(connection, """
            INSERT INTO nodes (space, path, generation) VALUES (@space, @path, 2)
            ON CONFLICT (space, path) DO UPDATE SET generation = nodes.generation + 1
            """, ("@space", space), ("@path", ""));
        var current = key;
        while (true)
        {
            upsert.Parameters["@path"].Value = current;
            upsert.ExecuteNonQuery();
            if (current.Length == 0) break;
            var slash = current.LastIndexOf('/');
            current = slash < 0 ? "" : current[..slash];
        }
    }

    /// <summary>Forgets a path and everything under it, then marks the folders above it changed.</summary>
    public void Deleted(string space, string path)
    {
        using var connection = database.Open();
        using var transaction = connection.BeginTransaction();
        DeleteTree(connection, space, Key(path));
        ChangedIn(connection, space, Parent(Key(path)));
        transaction.Commit();
    }

    /// <summary>A file or folder has moved: it and everything under it keep their ids and properties. Anything it replaced
    /// is forgotten.</summary>
    public void Moved(string fromSpace, string fromPath, string toSpace, string toPath)
    {
        var from = Key(fromPath);
        var to = Key(toPath);
        using var connection = database.Open();
        using var transaction = connection.BeginTransaction();
        DeleteTree(connection, toSpace, to);
        using (var move = Database.Command(connection, """
            UPDATE nodes SET space = @toSpace, path = @to || substr(path, length(@from) + 1)
            WHERE space = @fromSpace AND (path = @from OR (path >= @from || '/' AND path < @from || '0'))
            """, ("@toSpace", toSpace), ("@to", to), ("@from", from), ("@fromSpace", fromSpace)))
        {
            move.ExecuteNonQuery();
        }
        ChangedIn(connection, fromSpace, Parent(from));
        ChangedIn(connection, toSpace, to);
        transaction.Commit();
    }

    /// <summary>A file or folder has been copied: the copy gets ids of its own and the original's properties.</summary>
    public void Copied(string fromSpace, string fromPath, string toSpace, string toPath)
    {
        var from = Key(fromPath);
        var to = Key(toPath);
        using var connection = database.Open();
        using var transaction = connection.BeginTransaction();
        DeleteTree(connection, toSpace, to);
        using (var select = Database.Command(connection, """
            SELECT DISTINCT n.path FROM nodes n JOIN node_props p ON p.node = n.id
            WHERE n.space = @space AND (n.path = @from OR (n.path >= @from || '/' AND n.path < @from || '0'))
            """, ("@space", fromSpace), ("@from", from)))
        using (var reader = select.ExecuteReader())
        {
            var withProps = new List<string>();
            while (reader.Read()) withProps.Add(reader.GetString(0));
            foreach (var path in withProps)
            {
                var target = to + path[from.Length..];
                using var make = Database.Command(connection, """
                    INSERT INTO nodes (space, path) VALUES (@space, @path)
                    ON CONFLICT (space, path) DO UPDATE SET generation = nodes.generation RETURNING id
                    """, ("@space", toSpace), ("@path", target));
                var id = (long)make.ExecuteScalar()!;
                using var copy = Database.Command(connection, """
                    INSERT OR REPLACE INTO node_props (node, ns, name, xml)
                    SELECT @id, p.ns, p.name, p.xml FROM node_props p JOIN nodes n ON n.id = p.node WHERE n.space = @space AND n.path = @path
                    """, ("@id", id), ("@space", fromSpace), ("@path", path));
                copy.ExecuteNonQuery();
            }
        }
        ChangedIn(connection, toSpace, to);
        transaction.Commit();
    }

    private static void DeleteTree(SqliteConnection connection, string space, string key)
    {
        using var delete = Database.Command(connection, "DELETE FROM nodes WHERE space = @space AND (path = @path OR (path >= @path || '/' AND path < @path || '0'))",
            ("@space", space), ("@path", key));
        delete.ExecuteNonQuery();
    }

    private static string Parent(string key)
    {
        var slash = key.LastIndexOf('/');
        return slash < 0 ? "" : key[..slash];
    }

    // ---- Properties ----------------------------------------------------------------------------------------------

    public const int MaxPropertiesPerNode = 256;
    public const int MaxPropertyBytes = 64 * 1024;

    /// <summary>All of a node's properties: namespace, name and the element as XML.</summary>
    public List<(string Ns, string Name, string Xml)> Properties(long node)
    {
        var properties = new List<(string, string, string)>();
        using var connection = database.Open();
        using var command = Database.Command(connection, "SELECT ns, name, xml FROM node_props WHERE node = @node", ("@node", node));
        using var reader = command.ExecuteReader();
        while (reader.Read()) properties.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        return properties;
    }

    /// <summary>Which of many nodes have properties at all, which is few of them, so that a listing needn't ask of each.</summary>
    public HashSet<long> WithProperties(IEnumerable<long> nodes)
    {
        var found = new HashSet<long>();
        using var connection = database.Open();
        using var command = Database.Command(connection, "SELECT 1 FROM node_props WHERE node = @node LIMIT 1", ("@node", 0L));
        foreach (var node in nodes)
        {
            command.Parameters["@node"].Value = node;
            if (command.ExecuteScalar() is not null) found.Add(node);
        }
        return found;
    }

    /// <summary>Applies a PROPPATCH: all of it or none. A null value removes the property. False if it would hold too many.</summary>
    public bool ChangeProperties(long node, IReadOnlyList<(string Ns, string Name, string? Xml)> changes)
    {
        using var connection = database.Open();
        using var transaction = connection.BeginTransaction();
        foreach (var (ns, name, xml) in changes)
        {
            if (xml is null)
            {
                using var delete = Database.Command(connection, "DELETE FROM node_props WHERE node = @node AND ns = @ns AND name = @name", ("@node", node), ("@ns", ns), ("@name", name));
                delete.ExecuteNonQuery();
            }
            else
            {
                using var set = Database.Command(connection, "INSERT OR REPLACE INTO node_props (node, ns, name, xml) VALUES (@node, @ns, @name, @xml)", ("@node", node), ("@ns", ns), ("@name", name), ("@xml", xml));
                set.ExecuteNonQuery();
            }
        }
        using (var count = Database.Command(connection, "SELECT COUNT(*) FROM node_props WHERE node = @node", ("@node", node)))
        {
            if ((long)count.ExecuteScalar()! > MaxPropertiesPerNode) return false;
        }
        transaction.Commit();
        return true;
    }
}
