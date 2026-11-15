using OntapNfs.Core.FileAccess;
using Xunit;

namespace OntapNfs.Tests.Core;

public sealed class NfsPathGuardTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Theory]
    [InlineData("webapps/app.war", "webapps/app.war")]
    [InlineData("./webapps//app.war", "webapps/app.war")]
    [InlineData("a/./b", "a/b")]
    public void Resolves_inside_root(string input, string expected)
    {
        var guard = new NfsPathGuard(_dir.Path);
        Assert.Equal(Path.Combine(_dir.Path, expected.Replace('/', Path.DirectorySeparatorChar)), guard.Resolve(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("./")]
    public void Empty_resolves_to_root(string input)
        => Assert.Equal(new NfsPathGuard(_dir.Path).Root, new NfsPathGuard(_dir.Path).Resolve(input));

    [Theory]
    [InlineData("../etc/passwd")]
    [InlineData("webapps/../../etc")]
    [InlineData("..")]
    [InlineData("/etc/passwd")]
    [InlineData("webapps\\..\\x")]
    [InlineData("C:/Windows")]
    [InlineData("file.war:stream")]
    [InlineData("a\0b")]
    public void Rejects_traversal(string input)
    {
        var guard = new NfsPathGuard(_dir.Path);
        var ex = Assert.Throws<PathTraversalException>(() => guard.Resolve(input));
        Assert.Equal(input, ex.RejectedPath);
        Assert.False(string.IsNullOrEmpty(ex.Reason));
    }

    [Fact]
    public void Root_must_be_absolute()
        => Assert.Throws<ArgumentException>(() => new NfsPathGuard("relative/root"));

    [Fact]
    public void Trailing_separator_on_root_is_normalised()
    {
        var guard = new NfsPathGuard(_dir.Path + Path.DirectorySeparatorChar);
        Assert.Equal(_dir.Path, guard.Root);
        Assert.True(guard.IsInsideRoot(_dir.Combine("x")));
    }

    [Fact]
    public void Sibling_with_common_prefix_is_outside()
    {
        var guard = new NfsPathGuard(_dir.Path);
        Assert.False(guard.IsInsideRoot(_dir.Path + "-evil"));
        Assert.True(guard.IsInsideRoot(_dir.Path));
    }

    [Fact]
    public void Symlink_leaving_root_is_rejected()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var outside = new TempDir();
        Directory.CreateSymbolicLink(_dir.Combine("escape"), outside.Path);
        var guard = new NfsPathGuard(_dir.Path);
        Assert.Throws<PathTraversalException>(() => guard.Resolve("escape/secret.txt"));
    }

    [Fact]
    public void Symlink_inside_root_is_allowed()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_dir.Combine("real"));
        Directory.CreateSymbolicLink(_dir.Combine("alias"), _dir.Combine("real"));
        var guard = new NfsPathGuard(_dir.Path);
        Assert.EndsWith(Path.Combine("alias", "f.txt"), guard.Resolve("alias/f.txt"));
    }

    [Fact]
    public void Exception_constructors()
    {
        Assert.NotNull(new PathTraversalException().Message);
        Assert.Equal("m", new PathTraversalException("m").RejectedPath);
        var inner = new InvalidOperationException();
        Assert.Same(inner, new PathTraversalException("m", inner).InnerException);
    }
}
