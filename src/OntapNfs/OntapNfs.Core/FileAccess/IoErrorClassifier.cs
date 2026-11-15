namespace OntapNfs.Core.FileAccess;

/// <summary>
/// Decides whether an I/O failure on an NFS mount is worth retrying.
/// </summary>
/// <remarks>
/// On Linux and macOS, .NET raises an <see cref="IOException"/> whose
/// <see cref="Exception.HResult"/> carries the raw errno for errors it does not
/// map to a more specific type. On Windows the HResult is
/// <c>0x8007xxxx</c> wrapping the Win32 error code.
/// </remarks>
public static class IoErrorClassifier
{
    /// <summary>EIO: soft mount timeout or a server side I/O error.</summary>
    public const int Eio = 5;

    /// <summary>EAGAIN or EWOULDBLOCK: a non blocking lock (flock over NLM) is held elsewhere.</summary>
    public const int Eagain = 11;

    /// <summary>EBUSY: resource busy.</summary>
    public const int Ebusy = 16;

    /// <summary>ETIMEDOUT: RPC timeout to the NFS server.</summary>
    public const int Etimedout = 110;

    /// <summary>ESTALE: the file handle no longer refers to an object on the server.</summary>
    public const int Estale = 116;

    /// <summary>ENOLCK: the lock manager (NLM, rpc.statd) is unavailable or out of locks.</summary>
    public const int Enolck = 37;

    private const int Win32SharingViolation = 32;
    private const int Win32LockViolation = 33;
    private const int Win32UnexpectedNetworkError = 59;
    private const int Win32NetnameDeleted = 64;
    private const int Win32SemaphoreTimeout = 121;

    private static readonly HashSet<int> TransientErrno = new() { Eio, Eagain, Ebusy, Etimedout, Estale, Enolck };

    private static readonly HashSet<int> TransientWin32 = new()
    {
        Win32SharingViolation,
        Win32LockViolation,
        Win32UnexpectedNetworkError,
        Win32NetnameDeleted,
        Win32SemaphoreTimeout,
    };

    /// <summary>Classifies an exception.</summary>
    public static IoFailureKind Classify(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        switch (exception)
        {
            case PathTraversalException:
            case FileNotFoundException:
            case DirectoryNotFoundException:
            case PathTooLongException:
            case EndOfStreamException:
                return IoFailureKind.Permanent;
            case UnauthorizedAccessException:
                return IoFailureKind.Permanent;
            case IOException io:
                return ClassifyHResult(io.HResult);
            default:
                return IoFailureKind.Permanent;
        }
    }

    /// <summary>True when <see cref="Classify"/> returns a transient kind.</summary>
    public static bool IsTransient(Exception exception) => Classify(exception) != IoFailureKind.Permanent;

    internal static IoFailureKind ClassifyHResult(int hresult)
    {
        if ((hresult & unchecked((int)0xFFFF0000)) == unchecked((int)0x80070000))
        {
            var win32 = hresult & 0xFFFF;
            return win32 switch
            {
                Win32SharingViolation or Win32LockViolation => IoFailureKind.LockContention,
                _ when TransientWin32.Contains(win32) => IoFailureKind.ServerUnavailable,
                _ => IoFailureKind.Permanent,
            };
        }

        if (!TransientErrno.Contains(hresult))
        {
            return IoFailureKind.Permanent;
        }

        return hresult switch
        {
            Estale => IoFailureKind.StaleHandle,
            Eagain or Ebusy or Enolck => IoFailureKind.LockContention,
            _ => IoFailureKind.ServerUnavailable,
        };
    }
}

/// <summary>How an I/O failure should be treated.</summary>
public enum IoFailureKind
{
    /// <summary>Do not retry: missing file, permission, traversal, or an unknown error.</summary>
    Permanent,

    /// <summary>ESTALE: reopen by path and retry.</summary>
    StaleHandle,

    /// <summary>Another client holds a conflicting lock or share mode.</summary>
    LockContention,

    /// <summary>The server did not answer in time (soft mount EIO, ETIMEDOUT, lost SMB or NFS session on Windows).</summary>
    ServerUnavailable,
}
