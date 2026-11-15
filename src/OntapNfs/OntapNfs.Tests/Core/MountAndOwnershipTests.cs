using OntapNfs.Core.FileAccess;
using OntapNfs.Core.Posix;
using Xunit;

namespace OntapNfs.Tests.Core;

public sealed class MountAndOwnershipTests
{
    private const string Mounts = """
        sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
        /dev/sda1 / ext4 rw,relatime 0 0
        svm1-data:/vol1 /mnt/ontap/vol1 nfs rw,relatime,vers=3,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=10.0.0.5,mountvers=3,mountport=635,mountproto=tcp,local_lock=none,addr=10.0.0.5 0 0
        svm1-data:/vol2 /mnt/ontap/vol2 nfs4 rw,relatime,vers=4.1,hard,proto=tcp 0 0
        nfssrv:/export/apps /mnt/with\040space nfs ro,vers=3,soft,nolock 0 0
        /dev/mapper/lun0 /srv/export xfs rw,relatime,inode64 0 0
        """;

    [Fact]
    public void Parses_mount_table()
    {
        var entries = MountTable.Parse(Mounts);
        Assert.Equal(6, entries.Count);
        var v1 = entries[2];
        Assert.True(v1.IsNfsV3);
        Assert.Equal("3", v1.NfsVersion);
        Assert.Equal("sys", v1.Option("sec"));
        Assert.False(v1.HasNoLock);
        Assert.False(v1.IsSoft);
        Assert.False(entries[3].IsNfsV3);
        Assert.True(entries[3].IsNfs);
        Assert.Equal("/mnt/with space", entries[4].MountPoint);
        Assert.True(entries[4].HasNoLock);
        Assert.True(entries[4].IsSoft);
        Assert.False(entries[5].IsNfs);
        Assert.Null(entries[5].NfsVersion);
    }

    [Theory]
    [InlineData("/mnt/ontap/vol1/opt/tomcat/webapps", "/mnt/ontap/vol1")]
    [InlineData("/mnt/ontap/vol1", "/mnt/ontap/vol1")]
    [InlineData("/mnt/ontap/vol10/x", "/")]
    [InlineData("/srv/export/finance", "/srv/export")]
    public void Finds_longest_mount(string path, string expected)
        => Assert.Equal(expected, MountTable.FindMountFor(MountTable.Parse(Mounts), path)?.MountPoint);

    [Fact]
    public void Unescape_leaves_invalid_sequences()
    {
        Assert.Equal("a\\9b", MountTable.Unescape("a\\9b"));
        Assert.Equal("a\\04", MountTable.Unescape("a\\04"));
        Assert.Equal("a\tb", MountTable.Unescape("a\\011b"));
    }

    [Fact]
    public void Reads_current_mount_table_on_linux()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Throws<PlatformNotSupportedException>(() => MountTable.ReadCurrent());
            return;
        }

        Assert.NotEmpty(MountTable.ReadCurrent());
    }

    [Fact]
    public void Statx_reader_returns_process_owner_and_mode()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var dir = new TempDir();
        var file = dir.Combine("owned");
        File.WriteAllText(file, "x");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);

        var reader = new LinuxFileOwnershipReader();
        var o = reader.Read(file);
        Assert.Equal(LinuxFileOwnershipReader.CurrentEffectiveUid(), o.Uid);
        Assert.Equal(File.GetUnixFileMode(file), o.Mode);
        Assert.True(o.Gid >= 0);
        var missing = dir.Combine("missing");
        FileNotFoundException? notFound = null;
        try
        {
            reader.Read(missing);
        }
        catch (FileNotFoundException ex)
        {
            notFound = ex;
        }

        Assert.NotNull(notFound);
        Assert.True(LinuxFileOwnershipReader.CurrentEffectiveGid() >= 0);
    }

    [Theory]
    [InlineData(1000, new long[] { 100 }, PosixPermissions.Want.Write, true)]
    [InlineData(2000, new long[] { 4100 }, PosixPermissions.Want.Write, true)]
    [InlineData(2000, new long[] { 4100 }, PosixPermissions.Want.Read, true)]
    [InlineData(3000, new long[] { 1 }, PosixPermissions.Want.Write, false)]
    [InlineData(3000, new long[] { 1 }, PosixPermissions.Want.Read, true)]
    [InlineData(0, new long[] { 0 }, PosixPermissions.Want.Write, true)]
    public void Mode_bits_pick_exactly_one_class(long uid, long[] gids, PosixPermissions.Want want, bool expected)
    {
        // drwxrwsr-x owner 1000 group 4100
        var dir = new PosixOwnership(1000, 4100, (UnixFileMode)Convert.ToInt32("2775", 8));
        Assert.Equal(expected, PosixPermissions.Allows(dir, uid, gids, want));
    }

    [Fact]
    public void Owner_class_wins_over_group_even_when_group_has_more()
    {
        var file = new PosixOwnership(1000, 4100, (UnixFileMode)Convert.ToInt32("0470", 8));
        Assert.False(PosixPermissions.Allows(file, 1000, new long[] { 4100 }, PosixPermissions.Want.Write));
        Assert.True(PosixPermissions.Allows(file, 1001, new long[] { 4100 }, PosixPermissions.Want.Write));
    }

    [Fact]
    public void Root_needs_an_execute_bit_to_execute()
    {
        var noX = new PosixOwnership(1, 1, (UnixFileMode)Convert.ToInt32("0644", 8));
        Assert.False(PosixPermissions.Allows(noX, 0, Array.Empty<long>(), PosixPermissions.Want.Execute));
        Assert.True(PosixPermissions.CanModifyDirectory(new PosixOwnership(1, 1, (UnixFileMode)Convert.ToInt32("0755", 8)), 0, Array.Empty<long>()));
    }
}
