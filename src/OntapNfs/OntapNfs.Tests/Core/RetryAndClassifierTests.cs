using OntapNfs.Core.FileAccess;
using Xunit;

namespace OntapNfs.Tests.Core;

public sealed class RetryAndClassifierTests
{
    [Theory]
    [InlineData(IoErrorClassifier.Estale, IoFailureKind.StaleHandle)]
    [InlineData(IoErrorClassifier.Eagain, IoFailureKind.LockContention)]
    [InlineData(IoErrorClassifier.Ebusy, IoFailureKind.LockContention)]
    [InlineData(IoErrorClassifier.Enolck, IoFailureKind.LockContention)]
    [InlineData(IoErrorClassifier.Eio, IoFailureKind.ServerUnavailable)]
    [InlineData(IoErrorClassifier.Etimedout, IoFailureKind.ServerUnavailable)]
    [InlineData(unchecked((int)0x80070020), IoFailureKind.LockContention)]
    [InlineData(unchecked((int)0x80070021), IoFailureKind.LockContention)]
    [InlineData(unchecked((int)0x80070040), IoFailureKind.ServerUnavailable)]
    [InlineData(unchecked((int)0x80070005), IoFailureKind.Permanent)]
    [InlineData(28, IoFailureKind.Permanent)]
    public void Classifies_hresults(int hresult, IoFailureKind expected)
        => Assert.Equal(expected, IoErrorClassifier.Classify(new IOException("x", hresult)));

    [Fact]
    public void Specific_exceptions_are_permanent()
    {
        Assert.False(IoErrorClassifier.IsTransient(new FileNotFoundException()));
        Assert.False(IoErrorClassifier.IsTransient(new DirectoryNotFoundException()));
        Assert.False(IoErrorClassifier.IsTransient(new UnauthorizedAccessException()));
        Assert.False(IoErrorClassifier.IsTransient(new PathTraversalException("../x", "parent")));
        Assert.False(IoErrorClassifier.IsTransient(new InvalidOperationException()));
        Assert.False(IoErrorClassifier.IsTransient(new EndOfStreamException()));
        Assert.False(IoErrorClassifier.IsTransient(new PathTooLongException()));
    }

    [Fact]
    public void Real_share_mode_conflict_is_classified_as_lock_contention()
    {
        using var dir = new TempDir();
        var path = dir.Combine("locked");
        using var holder = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        var ex = Assert.ThrowsAny<IOException>(() => new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None));
        Assert.Equal(IoFailureKind.LockContention, IoErrorClassifier.Classify(ex));
    }

    [Fact]
    public void Backoff_doubles_and_caps()
    {
        var p = new RetryPolicy(10, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(500));
        Assert.Equal(TimeSpan.FromMilliseconds(100), p.DelayAfter(1));
        Assert.Equal(TimeSpan.FromMilliseconds(200), p.DelayAfter(2));
        Assert.Equal(TimeSpan.FromMilliseconds(400), p.DelayAfter(3));
        Assert.Equal(TimeSpan.FromMilliseconds(500), p.DelayAfter(4));
        Assert.Equal(TimeSpan.FromMilliseconds(500), p.DelayAfter(60));
    }

    [Fact]
    public async Task Retries_transient_then_succeeds()
    {
        var delays = new List<TimeSpan>();
        var policy = new RetryPolicy(4, TimeSpan.FromMilliseconds(10), TimeSpan.FromSeconds(1), (d, _) =>
        {
            delays.Add(d);
            return Task.CompletedTask;
        });
        var events = new List<RetryEventArgs>();
        policy.Retrying += (_, e) => events.Add(e);
        var calls = 0;

        var result = await policy.ExecuteAsync(_ =>
        {
            calls++;
            if (calls < 3)
            {
                throw new IOException("stale", IoErrorClassifier.Estale);
            }

            return Task.FromResult(42);
        });

        Assert.Equal(42, result);
        Assert.Equal(3, calls);
        Assert.Equal(new[] { TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(20) }, delays);
        Assert.Equal(2, events.Count);
        Assert.All(events, e => Assert.Equal(IoFailureKind.StaleHandle, e.Kind));
        Assert.Equal(1, events[0].FailedAttempt);
        Assert.IsType<IOException>(events[1].Exception);
        Assert.Equal(TimeSpan.FromMilliseconds(20), events[1].Delay);
    }

    [Fact]
    public async Task Gives_up_after_max_attempts()
    {
        var policy = new RetryPolicy(3, TimeSpan.Zero, TimeSpan.Zero, (_, _) => Task.CompletedTask);
        var calls = 0;
        await Assert.ThrowsAsync<IOException>(() => policy.ExecuteAsync(_ =>
        {
            calls++;
            throw new IOException("busy", IoErrorClassifier.Ebusy);
        }));
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task Does_not_retry_permanent()
    {
        var policy = new RetryPolicy(5, TimeSpan.Zero, TimeSpan.Zero, (_, _) => Task.CompletedTask);
        var calls = 0;
        await Assert.ThrowsAsync<FileNotFoundException>(() => policy.ExecuteAsync(_ =>
        {
            calls++;
            throw new FileNotFoundException();
        }));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Honours_cancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(() => RetryPolicy.Default.ExecuteAsync(_ => Task.CompletedTask, cts.Token));
    }

    [Fact]
    public void Validates_arguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetryPolicy(0, TimeSpan.Zero, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RetryPolicy(1, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => RetryPolicy.Default.DelayAfter(0));
        Assert.Equal(1, RetryPolicy.None.MaxAttempts);
        Assert.Equal(5, RetryPolicy.Default.MaxAttempts);
    }

    [Fact]
    public void Synchronous_execute_retries()
    {
        var policy = new RetryPolicy(2, TimeSpan.Zero, TimeSpan.Zero, (_, _) => Task.CompletedTask);
        var calls = 0;
        var value = policy.Execute(() =>
        {
            if (++calls == 1)
            {
                throw new IOException("again", IoErrorClassifier.Eagain);
            }

            return "ok";
        });
        Assert.Equal("ok", value);
    }
}
