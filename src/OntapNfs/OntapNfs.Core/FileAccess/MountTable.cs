namespace OntapNfs.Core.FileAccess;

/// <summary>One line of <c>/proc/self/mounts</c>.</summary>
/// <param name="Source">Device or <c>server:/export</c>.</param>
/// <param name="MountPoint">Mount directory.</param>
/// <param name="FileSystemType">Type, for example <c>nfs</c>, <c>nfs4</c>, <c>ext4</c>, <c>xfs</c>.</param>
/// <param name="Options">Mount options in order.</param>
public sealed record MountEntry(string Source, string MountPoint, string FileSystemType, IReadOnlyList<string> Options)
{
    /// <summary>True for an NFS mount of any version.</summary>
    public bool IsNfs => FileSystemType is "nfs" or "nfs4";

    /// <summary>The NFS protocol version from <c>vers=</c> or <c>nfsvers=</c>, if present.</summary>
    public string? NfsVersion => Option("vers") ?? Option("nfsvers");

    /// <summary>True when this is an NFSv3 mount.</summary>
    public bool IsNfsV3 => IsNfs && NfsVersion is "3";

    /// <summary>True when the mount was made with <c>nolock</c>, which disables NLM.</summary>
    public bool HasNoLock => Options.Contains("nolock");

    /// <summary>True for a soft mount, which can surface EIO under server delay.</summary>
    public bool IsSoft => Options.Contains("soft");

    /// <summary>Value of a <c>key=value</c> option.</summary>
    public string? Option(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var prefix = key + "=";
        return Options.LastOrDefault(o => o.StartsWith(prefix, StringComparison.Ordinal))?.Substring(prefix.Length);
    }
}

/// <summary>Parses the Linux mount table and finds the mount that holds a path.</summary>
public static class MountTable
{
    /// <summary>Parses the text of <c>/proc/self/mounts</c>.</summary>
    public static IReadOnlyList<MountEntry> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new List<MountEntry>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 4)
            {
                continue;
            }

            result.Add(new MountEntry(
                Unescape(fields[0]),
                Unescape(fields[1]),
                fields[2],
                fields[3].Split(',', StringSplitOptions.RemoveEmptyEntries)));
        }

        return result;
    }

    /// <summary>Reads and parses <c>/proc/self/mounts</c>. Linux only.</summary>
    public static IReadOnlyList<MountEntry> ReadCurrent()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The mount table is read from /proc/self/mounts on Linux only.");
        }

        return Parse(File.ReadAllText("/proc/self/mounts"));
    }

    /// <summary>The mount with the longest mount point that contains the path.</summary>
    public static MountEntry? FindMountFor(IEnumerable<MountEntry> mounts, string absolutePath)
    {
        ArgumentNullException.ThrowIfNull(mounts);
        ArgumentException.ThrowIfNullOrWhiteSpace(absolutePath);
        var path = absolutePath.Length > 1 ? absolutePath.TrimEnd('/') : absolutePath;
        MountEntry? best = null;
        foreach (var m in mounts)
        {
            var mp = m.MountPoint.Length > 1 ? m.MountPoint.TrimEnd('/') : m.MountPoint;
            var contains = mp == "/"
                || path == mp
                || path.StartsWith(mp + "/", StringComparison.Ordinal);
            if (contains && (best is null || mp.Length >= best.MountPoint.TrimEnd('/').Length))
            {
                best = m;
            }
        }

        return best;
    }

    /// <summary>The kernel escapes space, tab, newline and backslash as three digit octal.</summary>
    internal static string Unescape(string field)
    {
        if (!field.Contains('\\', StringComparison.Ordinal))
        {
            return field;
        }

        var sb = new System.Text.StringBuilder(field.Length);
        for (var i = 0; i < field.Length; i++)
        {
            if (field[i] == '\\' && IsOctal(field, i + 1))
            {
                sb.Append((char)Convert.ToInt32(field.Substring(i + 1, 3), 8));
                i += 3;
            }
            else
            {
                sb.Append(field[i]);
            }
        }

        return sb.ToString();
    }

    private static bool IsOctal(string s, int start)
    {
        if (start + 3 > s.Length)
        {
            return false;
        }

        for (var k = start; k < start + 3; k++)
        {
            if (s[k] < '0' || s[k] > '7')
            {
                return false;
            }
        }

        return true;
    }
}
