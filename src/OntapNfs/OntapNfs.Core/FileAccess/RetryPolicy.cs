namespace OntapNfs.Core.FileAccess;

/// <summary>
/// Retries an operation on transient NFS failures with capped exponential backoff.
/// Every attempt reopens by path, which is what recovers from ESTALE.
/// </summary>
public sealed class RetryPolicy
{
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    /// <summary>Creates a policy.</summary>
    /// <param name="maxAttempts">Total attempts including the first; at least 1.</param>
    /// <param name="baseDelay">Delay before the second attempt; doubles for each further attempt.</param>
    /// <param name="maxDelay">Upper bound for any single delay.</param>
    /// <param name="delay">Delay function, replaceable in tests.</param>
    public RetryPolicy(int maxAttempts, TimeSpan baseDelay, TimeSpan maxDelay, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAttempts, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(baseDelay, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxDelay, baseDelay);
        MaxAttempts = maxAttempts;
        BaseDelay = baseDelay;
        MaxDelay = maxDelay;
        _delay = delay ?? Task.Delay;
    }

    /// <summary>Five attempts, 200 ms doubling to at most 5 s: about 3 s of waiting in total.</summary>
    public static RetryPolicy Default { get; } = new(5, TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(5));

    /// <summary>A single attempt with no retry.</summary>
    public static RetryPolicy None { get; } = new(1, TimeSpan.Zero, TimeSpan.Zero);

    /// <summary>Total attempts.</summary>
    public int MaxAttempts { get; }

    /// <summary>First backoff delay.</summary>
    public TimeSpan BaseDelay { get; }

    /// <summary>Delay cap.</summary>
    public TimeSpan MaxDelay { get; }

    /// <summary>Raised before each retry with the attempt number that failed and the exception.</summary>
    public event EventHandler<RetryEventArgs>? Retrying;

    /// <summary>The delay that follows a failed attempt (1 based).</summary>
    public TimeSpan DelayAfter(int failedAttempt)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(failedAttempt, 1);
        var factor = Math.Pow(2, Math.Min(failedAttempt - 1, 30));
        var ticks = Math.Min(BaseDelay.Ticks * factor, MaxDelay.Ticks);
        return TimeSpan.FromTicks((long)ticks);
    }

    /// <summary>Runs an operation, retrying on transient I/O failures.</summary>
    public async Task<T> ExecuteAsync<T>(Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await operation(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (attempt < MaxAttempts && IoErrorClassifier.IsTransient(ex))
            {
                var wait = DelayAfter(attempt);
                Retrying?.Invoke(this, new RetryEventArgs(attempt, IoErrorClassifier.Classify(ex), wait, ex));
                await _delay(wait, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Runs an operation with no result, retrying on transient I/O failures.</summary>
    public Task ExecuteAsync(Func<CancellationToken, Task> operation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return ExecuteAsync<bool>(async ct =>
        {
            await operation(ct).ConfigureAwait(false);
            return true;
        }, cancellationToken);
    }

    /// <summary>Runs a synchronous operation, retrying on transient I/O failures.</summary>
    public T Execute<T>(Func<T> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return ExecuteAsync(_ => Task.FromResult(operation())).GetAwaiter().GetResult();
    }
}

/// <summary>Details of one retry.</summary>
public sealed class RetryEventArgs : EventArgs
{
    internal RetryEventArgs(int failedAttempt, IoFailureKind kind, TimeSpan delay, Exception exception)
    {
        FailedAttempt = failedAttempt;
        Kind = kind;
        Delay = delay;
        Exception = exception;
    }

    /// <summary>The 1 based attempt that failed.</summary>
    public int FailedAttempt { get; }

    /// <summary>Classification of the failure.</summary>
    public IoFailureKind Kind { get; }

    /// <summary>The wait before the next attempt.</summary>
    public TimeSpan Delay { get; }

    /// <summary>The failure.</summary>
    public Exception Exception { get; }
}
