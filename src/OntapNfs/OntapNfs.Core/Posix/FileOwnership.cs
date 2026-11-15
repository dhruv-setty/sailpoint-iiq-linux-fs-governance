using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace OntapNfs.Core.Posix;

/// <summary>Owner, group and mode bits of a file as the NFS client reports them.</summary>
/// <param name="Uid">Owning UID (after any server side squash at creation time).</param>
/// <param name="Gid">Owning GID.</param>
/// <param name="Mode">Permission bits including setuid, setgid and sticky.</param>
public sealed record PosixOwnership(long Uid, long Gid, UnixFileMode Mode);

/// <summary>Reads POSIX ownership. Abstracted so validation can be tested without a real mount.</summary>
public interface IFileOwnershipReader
{
    /// <summary>Reads ownership of a path without following a final symbolic link.</summary>
    PosixOwnership Read(string path);
}

/// <summary>
/// Linux implementation over <c>statx(2)</c>. <c>struct statx</c> has the same layout
/// on every Linux architecture, unlike <c>struct stat</c>, so it is safe to read by offset.
/// It needs glibc 2.28 or later (RHEL 8, Ubuntu 18.10) and kernel 4.11 or later.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxFileOwnershipReader : IFileOwnershipReader
{
    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;
    private const uint StatxType = 0x1;
    private const uint StatxMode = 0x2;
    private const uint StatxUid = 0x8;
    private const uint StatxGid = 0x10;
    private const int StatxSize = 256;
    private const int OffsetMask = 0;
    private const int OffsetUid = 20;
    private const int OffsetGid = 24;
    private const int OffsetMode = 28;

    /// <inheritdoc />
    public PosixOwnership Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var buffer = new byte[StatxSize];
        var rc = NativeMethods.statx(AtFdCwd, path, AtSymlinkNoFollow, StatxType | StatxMode | StatxUid | StatxGid, buffer);
        if (rc != 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            if (errno == 2)
            {
                throw new FileNotFoundException("No such file: " + path, path);
            }

            throw new IOException($"statx failed for '{path}' with errno {errno}", errno);
        }

        var mask = BitConverter.ToUInt32(buffer, OffsetMask);
        if ((mask & (StatxUid | StatxGid)) != (StatxUid | StatxGid))
        {
            throw new IOException($"statx did not return owner fields for '{path}'");
        }

        var uid = BitConverter.ToUInt32(buffer, OffsetUid);
        var gid = BitConverter.ToUInt32(buffer, OffsetGid);
        var mode = (UnixFileMode)(BitConverter.ToUInt16(buffer, OffsetMode) & 0xFFF);
        return new PosixOwnership(uid, gid, mode);
    }

    /// <summary>Effective UID of this process.</summary>
    public static long CurrentEffectiveUid() => NativeMethods.geteuid();

    /// <summary>Effective GID of this process.</summary>
    public static long CurrentEffectiveGid() => NativeMethods.getegid();

    private static class NativeMethods
    {
        [DllImport("libc", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
#pragma warning disable CA2101 // UTF 8 marshalling is stated explicitly below.
        internal static extern int statx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, int flags, uint mask, [Out] byte[] statxbuf);
#pragma warning restore CA2101

        [DllImport("libc")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        internal static extern uint geteuid();

        [DllImport("libc")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        internal static extern uint getegid();
    }
}

/// <summary>Permission bit evaluation as an NFSv3 server does for AUTH_SYS (ACLs not considered).</summary>
public static class PosixPermissions
{
    /// <summary>Requested access.</summary>
    [Flags]
    public enum Want
    {
        /// <summary>Nothing.</summary>
        None = 0,

        /// <summary>Read.</summary>
        Read = 4,

        /// <summary>Write.</summary>
        Write = 2,

        /// <summary>Execute, or search for a directory.</summary>
        Execute = 1,
    }

    /// <summary>
    /// True when the identity has the wanted bits. Exactly one class applies: owner,
    /// then group (primary or supplementary), then other. UID 0 passes read and write;
    /// execute still needs some x bit, as on Linux.
    /// </summary>
    public static bool Allows(PosixOwnership ownership, long uid, IEnumerable<long> gids, Want want)
    {
        ArgumentNullException.ThrowIfNull(ownership);
        ArgumentNullException.ThrowIfNull(gids);
        var mode = (int)ownership.Mode;
        if (uid == UnixIds.Root)
        {
            return (want & Want.Execute) == 0 || (mode & 0b001_001_001) != 0;
        }

        int bits;
        if (uid == ownership.Uid)
        {
            bits = (mode >> 6) & 7;
        }
        else if (gids.Contains(ownership.Gid))
        {
            bits = (mode >> 3) & 7;
        }
        else
        {
            bits = mode & 7;
        }

        return (bits & (int)want) == (int)want;
    }

    /// <summary>Creating, renaming or deleting entries in a directory needs write and search.</summary>
    public static bool CanModifyDirectory(PosixOwnership directory, long uid, IEnumerable<long> gids)
        => Allows(directory, uid, gids, Want.Write | Want.Execute);
}
