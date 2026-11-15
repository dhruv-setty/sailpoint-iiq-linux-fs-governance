using System.Text;
using OntapNfs.Core.FileAccess;
using Xunit;

namespace OntapNfs.Tests.Core;

public sealed class NfsShareTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly NfsShare _share;

    public NfsShareTests()
    {
        _share = new NfsShare(_dir.Path, new RetryPolicy(3, TimeSpan.Zero, TimeSpan.Zero, (_, _) => Task.CompletedTask));
    }

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task Atomic_write_creates_parents_and_leaves_no_temp()
    {
        var path = await _share.WriteAllTextAtomicAsync("a/b/c.txt", "hello");
        Assert.Equal(_dir.Combine("a", "b", "c.txt"), path);
        Assert.Equal("hello", await _share.ReadAllTextAsync("a/b/c.txt"));
        Assert.Equal(new[] { "c.txt" }, Directory.GetFiles(_dir.Combine("a", "b")).Select(Path.GetFileName));
    }

    [Fact]
    public async Task Atomic_write_replaces_existing_file()
    {
        await _share.WriteAllTextAtomicAsync("f.txt", "one");
        await _share.WriteAllTextAtomicAsync("f.txt", "two");
        Assert.Equal("two", await _share.ReadAllTextAsync("f.txt"));
    }

    [Fact]
    public async Task Reader_holding_old_file_keeps_old_content_after_replace()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await _share.WriteAllTextAtomicAsync("f.txt", "old");
        using var reader = _share.OpenRead("f.txt");
        await _share.WriteAllTextAtomicAsync("f.txt", "new");
        using var sr = new StreamReader(reader);
        Assert.Equal("old", await sr.ReadToEndAsync());
        Assert.Equal("new", await _share.ReadAllTextAsync("f.txt"));
    }

    [Fact]
    public async Task Failed_writer_removes_temp_and_keeps_original()
    {
        await _share.WriteAllTextAtomicAsync("f.txt", "keep");
        await Assert.ThrowsAsync<InvalidOperationException>(() => _share.WriteAtomicAsync("f.txt", (_, _) => throw new InvalidOperationException("boom")));
        Assert.Equal("keep", await _share.ReadAllTextAsync("f.txt"));
        Assert.Single(Directory.GetFiles(_dir.Path));
    }

    [Fact]
    public async Task Transient_writer_failure_is_retried()
    {
        var calls = 0;
        await _share.WriteAtomicAsync("r.bin", async (s, ct) =>
        {
            if (++calls == 1)
            {
                throw new IOException("stale", IoErrorClassifier.Estale);
            }

            await s.WriteAsync(new byte[] { 1, 2, 3 }, ct);
        });
        Assert.Equal(2, calls);
        Assert.Equal(new byte[] { 1, 2, 3 }, await _share.ReadAllBytesAsync("r.bin"));
        Assert.Single(Directory.GetFiles(_dir.Path));
    }

    [Fact]
    public async Task Copy_in_from_outside_share()
    {
        using var src = new TempDir();
        var source = src.Combine("in.bin");
        await File.WriteAllBytesAsync(source, Encoding.ASCII.GetBytes("payload"));
        await _share.CopyInAtomicAsync(source, "dest/out.bin");
        Assert.Equal("payload", await _share.ReadAllTextAsync("dest/out.bin"));
    }

    [Fact]
    public void Exclusive_open_blocks_second_exclusive_open()
    {
        var single = new NfsShare(_dir.Path, RetryPolicy.None);
        using var first = single.OpenExclusive("lock");
        Assert.ThrowsAny<IOException>(() => single.OpenExclusive("lock"));
    }

    [Fact]
    public void Exclusive_open_is_retried_until_released()
    {
        var holder = new FileStream(_dir.Combine("lock"), FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        var share = new NfsShare(_dir.Path, new RetryPolicy(3, TimeSpan.Zero, TimeSpan.Zero, (_, _) =>
        {
            holder.Dispose();
            return Task.CompletedTask;
        }));
        using var second = share.OpenExclusive("lock");
        Assert.True(second.CanWrite);
    }

    [Fact]
    public async Task Helpers_cover_exists_delete_list_and_times()
    {
        Assert.False(_share.FileExists("x.txt"));
        Assert.Null(_share.GetLastWriteTimeUtc("x.txt"));
        await _share.WriteAllTextAtomicAsync("d/x.txt", "1");
        await _share.WriteAllTextAtomicAsync("d/y.txt", "2");
        Assert.True(_share.FileExists("d/x.txt"));
        Assert.True(_share.DirectoryExists("d"));
        Assert.NotNull(_share.GetLastWriteTimeUtc("d/x.txt"));
        Assert.Equal(new[] { "x.txt", "y.txt" }, _share.ListFiles("d"));
        Assert.Empty(_share.ListFiles("missing"));
        Assert.True(_share.DeleteFile("d/x.txt"));
        Assert.False(_share.DeleteFile("d/x.txt"));
        Assert.Equal(_dir.Combine("e", "f"), _share.EnsureDirectory("e/f"));
        Assert.Equal(_dir.Path, _share.Root);
    }

    [Fact]
    public async Task Rejects_traversal_and_directory_targets()
    {
        await Assert.ThrowsAsync<PathTraversalException>(() => _share.WriteAllTextAtomicAsync("../x", "no"));
        await Assert.ThrowsAsync<ArgumentException>(() => _share.WriteAllTextAtomicAsync("", "no"));
        Assert.Throws<PathTraversalException>(() => _share.OpenRead("/etc/passwd"));
    }

    [Fact]
    public void Temp_names_are_hidden_and_recognised()
    {
        var name = NfsShare.TempNameFor("app.war");
        Assert.StartsWith(".app.war.", name, StringComparison.Ordinal);
        Assert.True(NfsShare.IsTempFile(name));
        Assert.False(NfsShare.IsTempFile("app.war"));
        Assert.False(NfsShare.IsTempFile(".app.war.dodeploy"));
    }
}
