using System.Text;

namespace OntapNfs.Core.FileAccess;

/// <summary>
/// File access on a mounted NFSv3 share through plain System.IO.
/// </summary>
/// <remarks>
/// <para>Every open states its <see cref="FileShare"/> mode explicitly. On Linux,
/// .NET turns <see cref="FileShare.None"/> into an advisory whole file
/// <c>flock(LOCK_EX)</c>, which the Linux NFS client carries to the server as an
/// NLM lock; any other share mode takes <c>LOCK_SH</c>. Locks are advisory, so only
/// cooperating writers that also lock are excluded.</para>
/// <para>Writes go to a temporary file in the target directory, are flushed to the
/// server, and then renamed over the destination. NFSv3 RENAME is atomic on the
/// server, so a reader on another client sees the old file or the new one, never
/// a partial write, once its attribute cache revalidates (close to open consistency).</para>
/// </remarks>
public sealed class NfsShare
{
    private const string TempSuffix = ".tmp";

    /// <summary>Creates a share accessor rooted at a mounted path.</summary>
    public NfsShare(string rootPath, RetryPolicy? retryPolicy = null)
    {
        Guard = new NfsPathGuard(rootPath);
        Retry = retryPolicy ?? RetryPolicy.Default;
    }

    /// <summary>The path guard for this share.</summary>
    public NfsPathGuard Guard { get; }

    /// <summary>The retry policy applied to each operation.</summary>
    public RetryPolicy Retry { get; }

    /// <summary>The share root.</summary>
    public string Root => Guard.Root;

    /// <summary>Resolves a relative path inside the share.</summary>
    public string Resolve(string relativePath) => Guard.Resolve(relativePath);

    /// <summary>True when the file exists.</summary>
    public bool FileExists(string relativePath) => File.Exists(Resolve(relativePath));

    /// <summary>True when the directory exists.</summary>
    public bool DirectoryExists(string relativePath) => Directory.Exists(Resolve(relativePath));

    /// <summary>Creates the directory and any missing parents.</summary>
    public string EnsureDirectory(string relativePath)
    {
        var full = Resolve(relativePath);
        Retry.Execute(() => Directory.CreateDirectory(full));
        return full;
    }

    /// <summary>Last write time as recorded by the NFS server.</summary>
    public DateTime? GetLastWriteTimeUtc(string relativePath)
    {
        var full = Resolve(relativePath);
        return Retry.Execute<DateTime?>(() =>
        {
            var info = new FileInfo(full);
            info.Refresh();
            return info.Exists ? info.LastWriteTimeUtc : null;
        });
    }

    /// <summary>Deletes a file if present. Returns true when a file was removed.</summary>
    public bool DeleteFile(string relativePath)
    {
        var full = Resolve(relativePath);
        return Retry.Execute(() =>
        {
            if (!File.Exists(full))
            {
                return false;
            }

            File.Delete(full);
            return true;
        });
    }

    /// <summary>Lists file names (not paths) in a directory matching a pattern.</summary>
    public IReadOnlyList<string> ListFiles(string relativeDirectory, string searchPattern = "*")
    {
        var full = Resolve(relativeDirectory);
        return Retry.Execute<IReadOnlyList<string>>(() => Directory.Exists(full)
            ? Directory.EnumerateFiles(full, searchPattern, SearchOption.TopDirectoryOnly)
                .Select(p => Path.GetFileName(p))
                .Order(StringComparer.Ordinal)
                .ToList()
            : Array.Empty<string>());
    }

    /// <summary>
    /// Opens a file for reading with <see cref="FileShare.Read"/>: other readers are
    /// allowed, writers that take an exclusive lock are not.
    /// </summary>
    public FileStream OpenRead(string relativePath)
    {
        var full = Resolve(relativePath);
        return Retry.Execute(() => new FileStream(full, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = System.IO.FileAccess.Read,
            Share = FileShare.Read,
            Options = FileOptions.SequentialScan,
        }));
    }

    /// <summary>
    /// Opens a file with <see cref="FileShare.None"/>, the closest System.IO gets to an
    /// exclusive NLM lock. Use it as a short lived mutex between cooperating clients.
    /// </summary>
    public FileStream OpenExclusive(string relativePath, FileMode mode = FileMode.OpenOrCreate)
    {
        var full = Resolve(relativePath);
        return Retry.Execute(() => new FileStream(full, mode, System.IO.FileAccess.ReadWrite, FileShare.None));
    }

    /// <summary>Reads a whole file.</summary>
    public Task<byte[]> ReadAllBytesAsync(string relativePath, CancellationToken cancellationToken = default)
    {
        var full = Resolve(relativePath);
        return Retry.ExecuteAsync(async ct =>
        {
            await using var stream = new FileStream(full, FileMode.Open, System.IO.FileAccess.Read, FileShare.Read);
            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, ct).ConfigureAwait(false);
            return buffer.ToArray();
        }, cancellationToken);
    }

    /// <summary>Reads a whole file as UTF 8 text.</summary>
    public async Task<string> ReadAllTextAsync(string relativePath, CancellationToken cancellationToken = default)
        => Encoding.UTF8.GetString(await ReadAllBytesAsync(relativePath, cancellationToken).ConfigureAwait(false));

    /// <summary>Atomically writes bytes to a file.</summary>
    public Task<string> WriteAllBytesAtomicAsync(string relativePath, ReadOnlyMemory<byte> content, CancellationToken cancellationToken = default)
        => WriteAtomicAsync(relativePath, (s, ct) => s.WriteAsync(content, ct).AsTask(), cancellationToken);

    /// <summary>Atomically writes UTF 8 text to a file.</summary>
    public Task<string> WriteAllTextAtomicAsync(string relativePath, string content, CancellationToken cancellationToken = default)
        => WriteAllBytesAtomicAsync(relativePath, Encoding.UTF8.GetBytes(content), cancellationToken);

    /// <summary>
    /// Copies a file from anywhere on the local system into the share atomically.
    /// The source is opened with <see cref="FileShare.Read"/>.
    /// </summary>
    public Task<string> CopyInAtomicAsync(string sourcePath, string relativeDestination, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        return WriteAtomicAsync(relativeDestination, async (target, ct) =>
        {
            await using var source = new FileStream(sourcePath, new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = System.IO.FileAccess.Read,
                Share = FileShare.Read,
                Options = FileOptions.SequentialScan | FileOptions.Asynchronous,
            });
            await source.CopyToAsync(target, ct).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>
    /// Writes through a temporary file in the destination directory, flushes it to
    /// the server, then renames it over the destination. Returns the final path.
    /// </summary>
    public Task<string> WriteAtomicAsync(string relativePath, Func<Stream, CancellationToken, Task> writer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(writer);
        var full = Resolve(relativePath);
        if (string.Equals(full, Root, StringComparison.Ordinal) || Directory.Exists(full))
        {
            throw new ArgumentException("Destination must name a file, not a directory: " + relativePath, nameof(relativePath));
        }

        var directory = Path.GetDirectoryName(full)
            ?? throw new ArgumentException("Destination has no parent directory: " + relativePath, nameof(relativePath));
        var fileName = Path.GetFileName(full);
        if (fileName.Length == 0)
        {
            throw new ArgumentException("Destination must name a file: " + relativePath, nameof(relativePath));
        }

        return Retry.ExecuteAsync(async ct =>
        {
            Directory.CreateDirectory(directory);
            var temp = Path.Combine(directory, TempNameFor(fileName));
            try
            {
                await using (var stream = new FileStream(temp, new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = System.IO.FileAccess.Write,
                    Share = FileShare.None,
                    Options = FileOptions.Asynchronous,
                }))
                {
                    await writer(stream, ct).ConfigureAwait(false);
                    await stream.FlushAsync(ct).ConfigureAwait(false);

                    // NFS COMMIT: make sure the server holds the data before the rename publishes it.
                    stream.Flush(flushToDisk: true);
                }

                File.Move(temp, full, overwrite: true);
                return full;
            }
            catch
            {
                TryDelete(temp);
                throw;
            }
        }, cancellationToken);
    }

    /// <summary>True when a file name looks like one of this class's temporary files.</summary>
    public static bool IsTempFile(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        return fileName.StartsWith('.') && fileName.EndsWith(TempSuffix, StringComparison.Ordinal);
    }

    /// <summary>
    /// Temporary name: hidden, unique, and ending in <c>.tmp</c> so Tomcat, Jetty and
    /// the WildFly deployment scanner ignore it while it is being written.
    /// </summary>
    internal static string TempNameFor(string fileName)
        => "." + fileName + "." + Guid.NewGuid().ToString("N")[..12] + TempSuffix;

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best effort: a leftover hidden .tmp file is harmless and recognisable.
        }
        catch (UnauthorizedAccessException)
        {
            // Same as above.
        }
    }
}
