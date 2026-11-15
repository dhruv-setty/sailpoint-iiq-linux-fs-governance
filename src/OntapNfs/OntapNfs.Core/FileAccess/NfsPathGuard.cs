namespace OntapNfs.Core.FileAccess;

/// <summary>
/// Resolves caller supplied relative paths against a share root and refuses
/// anything that would land outside it: rooted paths, parent segments,
/// backslashes, NUL characters and symbolic links whose target leaves the root.
/// </summary>
/// <remarks>
/// The root can be a Linux mount directory (<c>/mnt/ontap/vol1</c>), a Windows
/// drive letter mapped by the Windows NFS client (<c>N:\</c>) or a UNC path
/// (<c>\\svm1\vol1</c>). Relative input always uses forward slashes so the same
/// relative path means the same file on every client platform.
/// </remarks>
public sealed class NfsPathGuard
{
    private readonly string _root;
    private readonly string _rootWithSeparator;
    private readonly StringComparison _comparison;

    /// <summary>Creates a guard for the given share root.</summary>
    /// <param name="rootPath">Absolute path of the mounted share.</param>
    public NfsPathGuard(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        if (!Path.IsPathFullyQualified(rootPath))
        {
            throw new ArgumentException("Share root must be an absolute path: " + rootPath, nameof(rootPath));
        }

        _root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath));
        if (_root.Length == 0)
        {
            _root = Path.GetFullPath(rootPath);
        }

        _rootWithSeparator = _root.EndsWith(Path.DirectorySeparatorChar)
            ? _root
            : _root + Path.DirectorySeparatorChar;
        _comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    }

    /// <summary>The normalised share root.</summary>
    public string Root => _root;

    /// <summary>
    /// Resolves a relative path to an absolute path inside the root.
    /// An empty string or <c>.</c> resolves to the root itself.
    /// </summary>
    /// <exception cref="PathTraversalException">The path escapes the root.</exception>
    public string Resolve(string relativePath)
    {
        ArgumentNullException.ThrowIfNull(relativePath);
        ValidateSyntax(relativePath);

        var segments = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Where(s => s != ".")
            .ToArray();
        var combined = segments.Length == 0 ? _root : Path.Combine(_root, Path.Combine(segments));
        var full = Path.GetFullPath(combined);

        if (!IsInsideRoot(full))
        {
            throw new PathTraversalException(relativePath, "resolves outside the share root");
        }

        EnsureNoEscapingLinks(full, relativePath);
        return full;
    }

    /// <summary>True when an absolute path is the root or below it, by string comparison only.</summary>
    public bool IsInsideRoot(string absolutePath)
    {
        ArgumentNullException.ThrowIfNull(absolutePath);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(absolutePath));
        return string.Equals(full, _root, _comparison)
            || full.StartsWith(_rootWithSeparator, _comparison);
    }

    private static void ValidateSyntax(string relativePath)
    {
        if (relativePath.Contains('\0', StringComparison.Ordinal))
        {
            throw new PathTraversalException(relativePath, "contains a NUL character");
        }

        if (relativePath.Contains('\\', StringComparison.Ordinal))
        {
            throw new PathTraversalException(relativePath, "contains a backslash; use forward slashes");
        }

        if (relativePath.StartsWith('/') || Path.IsPathRooted(relativePath) || HasDriveOrStreamColon(relativePath))
        {
            throw new PathTraversalException(relativePath, "is rooted; a path relative to the share root is required");
        }

        foreach (var segment in relativePath.Split('/'))
        {
            if (segment == "..")
            {
                throw new PathTraversalException(relativePath, "contains a parent directory segment");
            }
        }
    }

    private static bool HasDriveOrStreamColon(string relativePath)
        => relativePath.Contains(':', StringComparison.Ordinal);

    /// <summary>
    /// Walks each existing component below the root. If any component is a
    /// symbolic link, its final target must still be inside the root.
    /// </summary>
    private void EnsureNoEscapingLinks(string full, string relativePath)
    {
        if (string.Equals(full, _root, _comparison))
        {
            return;
        }

        var relative = full.Substring(_rootWithSeparator.Length);
        var current = _root;
        foreach (var part in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            if (!info.Exists)
            {
                return;
            }

            if (info.LinkTarget is null)
            {
                continue;
            }

            var target = info.ResolveLinkTarget(returnFinalTarget: true);
            var targetPath = target?.FullName
                ?? Path.GetFullPath(info.LinkTarget, Path.GetDirectoryName(current) ?? _root);
            if (!IsInsideRoot(targetPath))
            {
                throw new PathTraversalException(relativePath, "follows a symbolic link outside the share root");
            }
        }
    }
}

/// <summary>Raised when a relative path would escape the share root.</summary>
public sealed class PathTraversalException : IOException
{
    /// <summary>Creates the exception.</summary>
    public PathTraversalException(string path, string reason)
        : base($"Path '{path}' rejected: {reason}.")
    {
        RejectedPath = path;
        Reason = reason;
    }

    /// <summary>Creates the exception with a default message.</summary>
    public PathTraversalException()
        : this(string.Empty, "rejected")
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public PathTraversalException(string message)
        : this(message, "rejected")
    {
    }

    /// <summary>Creates the exception with a message and inner exception.</summary>
    public PathTraversalException(string message, Exception innerException)
        : base(message, innerException)
    {
        RejectedPath = string.Empty;
        Reason = message;
    }

    /// <summary>The rejected input.</summary>
    public string RejectedPath { get; }

    /// <summary>Why it was rejected.</summary>
    public string Reason { get; }
}
