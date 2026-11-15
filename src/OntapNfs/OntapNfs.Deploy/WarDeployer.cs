using System.IO.Compression;
using System.Text.RegularExpressions;
using OntapNfs.Core.FileAccess;

namespace OntapNfs.Deploy;

/// <summary>Java application server whose deployment directory sits on the NFS share.</summary>
public enum AppServerKind
{
    /// <summary>Apache Tomcat: <c>$CATALINA_BASE/webapps</c> with autoDeploy.</summary>
    Tomcat,

    /// <summary>WildFly or JBoss EAP: <c>standalone/deployments</c> with the deployment scanner and marker files.</summary>
    WildFly,

    /// <summary>Eclipse Jetty: <c>$JETTY_BASE/webapps</c> with the deployment manager scanner.</summary>
    Jetty,
}

/// <summary>Outcome of a deployment.</summary>
public enum DeploymentStatus
{
    /// <summary>The WAR is in place; Tomcat or Jetty picks it up on its next scan.</summary>
    Copied,

    /// <summary>WildFly wrote the <c>.deployed</c> marker.</summary>
    Deployed,

    /// <summary>WildFly wrote the <c>.failed</c> marker.</summary>
    Failed,

    /// <summary>No marker appeared before the timeout. The scanner may be stopped or disabled.</summary>
    TimedOut,
}

/// <summary>Result of <see cref="WarDeployer.DeployAsync"/>.</summary>
/// <param name="Status">Outcome.</param>
/// <param name="WarPath">Absolute path of the deployed WAR.</param>
/// <param name="MarkerPath">The marker that decided the outcome, for WildFly.</param>
/// <param name="Message">Explanation; for a failure, the text WildFly wrote into the <c>.failed</c> marker.</param>
/// <param name="Elapsed">Time from start to outcome.</param>
public sealed record DeploymentResult(DeploymentStatus Status, string WarPath, string? MarkerPath, string Message, TimeSpan Elapsed);

/// <summary>Settings for <see cref="WarDeployer"/>.</summary>
public sealed class WarDeploymentOptions
{
    /// <summary>Server type.</summary>
    public required AppServerKind Kind { get; init; }

    /// <summary>
    /// Deployment directory relative to the share root, for example <c>opt/tomcat/webapps</c>,
    /// <c>opt/wildfly/standalone/deployments</c> or <c>opt/jetty-base/webapps</c>.
    /// </summary>
    public required string DeploymentDirectory { get; init; }

    /// <summary>How long to wait for a WildFly marker.</summary>
    public TimeSpan MarkerTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Marker poll interval. Keep it above the NFS attribute cache time (actimeo) of the polling client.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>Reject archives with no <c>WEB-INF/</c> entry.</summary>
    public bool RequireWebInf { get; init; } = true;
}

/// <summary>
/// Places a WAR into an application server deployment directory on an NFS share
/// so that the scanner never sees a partial file: copy to a hidden <c>.tmp</c> in the
/// same directory, flush, rename to <c>name.war</c>, and for WildFly drive the
/// marker file protocol.
/// </summary>
public sealed partial class WarDeployer
{
    /// <summary>WildFly marker suffixes, appended to the deployment file name.</summary>
    public static class Markers
    {
        /// <summary>Request deployment.</summary>
        public const string DoDeploy = ".dodeploy";

        /// <summary>Deployment in progress.</summary>
        public const string IsDeploying = ".isdeploying";

        /// <summary>Deployed.</summary>
        public const string Deployed = ".deployed";

        /// <summary>Failed; content holds the failure description.</summary>
        public const string Failed = ".failed";

        /// <summary>Undeployed.</summary>
        public const string Undeployed = ".undeployed";

        /// <summary>Auto deploy is suppressed for this content.</summary>
        public const string SkipDeploy = ".skipdeploy";

        /// <summary>Scanner noticed content but is waiting for it to be complete.</summary>
        public const string Pending = ".pending";
    }

    private readonly NfsShare _share;
    private readonly WarDeploymentOptions _options;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly TimeProvider _time;

    /// <summary>Creates a deployer.</summary>
    public WarDeployer(NfsShare share, WarDeploymentOptions options, Func<TimeSpan, CancellationToken, Task>? delay = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(share);
        ArgumentNullException.ThrowIfNull(options);
        _share = share;
        _options = options;
        _delay = delay ?? Task.Delay;
        _time = timeProvider ?? TimeProvider.System;
        DeploymentDirectory = share.Resolve(options.DeploymentDirectory);
    }

    /// <summary>Absolute deployment directory.</summary>
    public string DeploymentDirectory { get; }

    /// <summary>Validates, copies and (for WildFly) waits for the outcome.</summary>
    /// <param name="sourceWarPath">Local path of the built WAR.</param>
    /// <param name="appName">Deployment name without <c>.war</c>; it becomes the context path on Tomcat and Jetty.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<DeploymentResult> DeployAsync(string sourceWarPath, string appName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceWarPath);
        var started = _time.GetTimestamp();
        var name = NormalizeAppName(appName);
        ValidateWar(sourceWarPath, _options.RequireWebInf);

        var warFile = name + ".war";
        var relDir = _options.DeploymentDirectory.TrimEnd('/');
        var relWar = relDir + "/" + warFile;
        _share.EnsureDirectory(relDir);

        if (_options.Kind == AppServerKind.WildFly)
        {
            // Stale outcome markers from an earlier attempt would be misread as this attempt's result.
            // .deployed is left alone: deleting it makes the scanner undeploy the running application.
            _share.DeleteFile(relWar + Markers.Failed);
            _share.DeleteFile(relWar + Markers.Undeployed);
            _share.DeleteFile(relWar + Markers.Pending);
        }

        var warPath = await _share.CopyInAtomicAsync(sourceWarPath, relWar, cancellationToken).ConfigureAwait(false);

        if (_options.Kind != AppServerKind.WildFly)
        {
            var scanner = _options.Kind == AppServerKind.Tomcat ? "Tomcat autoDeploy" : "the Jetty deployment manager";
            return new DeploymentResult(DeploymentStatus.Copied, warPath, null,
                $"{warFile} renamed into place; {scanner} picks it up on its next scan", _time.GetElapsedTime(started));
        }

        var doDeploy = await _share.WriteAllTextAtomicAsync(relWar + Markers.DoDeploy, warFile, cancellationToken).ConfigureAwait(false);
        return await WaitForWildFlyAsync(relWar, warPath, doDeploy, started, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Removes hidden temporary files older than the given age left by an interrupted copy.</summary>
    public IReadOnlyList<string> RemoveStaleTempFiles(TimeSpan olderThan)
    {
        var removed = new List<string>();
        var cutoff = _time.GetUtcNow().UtcDateTime - olderThan;
        var relDir = _options.DeploymentDirectory.TrimEnd('/');
        foreach (var file in _share.ListFiles(relDir, ".*"))
        {
            if (!NfsShare.IsTempFile(file))
            {
                continue;
            }

            var rel = relDir + "/" + file;
            if (_share.GetLastWriteTimeUtc(rel) is { } written && written < cutoff && _share.DeleteFile(rel))
            {
                removed.Add(file);
            }
        }

        return removed;
    }

    /// <summary>Accepts <c>name</c> or <c>name.war</c>; letters, digits, dot, underscore, hyphen and Tomcat's <c>#</c>.</summary>
    public static string NormalizeAppName(string appName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appName);
        var name = appName.EndsWith(".war", StringComparison.OrdinalIgnoreCase) ? appName[..^4] : appName;
        if (!AppNamePattern().IsMatch(name) || name.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException($"'{appName}' is not a valid deployment name.", nameof(appName));
        }

        return name;
    }

    /// <summary>Checks the file is a readable ZIP and, when required, contains <c>WEB-INF/</c>.</summary>
    /// <exception cref="InvalidDataException">Not a ZIP archive or no WEB-INF.</exception>
    public static void ValidateWar(string path, bool requireWebInf = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        if (zip.Entries.Count == 0)
        {
            throw new InvalidDataException($"{path} is an empty archive.");
        }

        if (requireWebInf && !zip.Entries.Any(e => e.FullName.StartsWith("WEB-INF/", StringComparison.Ordinal)))
        {
            throw new InvalidDataException($"{path} has no WEB-INF/ entry and does not look like a web application archive.");
        }
    }

    private async Task<DeploymentResult> WaitForWildFlyAsync(string relWar, string warPath, string doDeployPath, long started, CancellationToken cancellationToken)
    {
        var failed = relWar + Markers.Failed;
        var deployed = relWar + Markers.Deployed;
        var waited = TimeSpan.Zero;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_share.FileExists(failed))
            {
                var reason = (await _share.ReadAllTextAsync(failed, cancellationToken).ConfigureAwait(false)).Trim();
                return new DeploymentResult(DeploymentStatus.Failed, warPath, _share.Resolve(failed),
                    reason.Length == 0 ? "WildFly reported failure without detail" : reason, _time.GetElapsedTime(started));
            }

            var consumed = !File.Exists(doDeployPath) && !_share.FileExists(relWar + Markers.IsDeploying);
            if (consumed && _share.FileExists(deployed))
            {
                return new DeploymentResult(DeploymentStatus.Deployed, warPath, _share.Resolve(deployed),
                    "WildFly deployment scanner reported success", _time.GetElapsedTime(started));
            }

            if (waited >= _options.MarkerTimeout)
            {
                var state = File.Exists(doDeployPath)
                    ? "the .dodeploy marker was never picked up; check that the deployment scanner is enabled and can see the share"
                    : "the scanner took the request but wrote neither .deployed nor .failed";
                return new DeploymentResult(DeploymentStatus.TimedOut, warPath, doDeployPath,
                    $"no outcome after {_options.MarkerTimeout}: {state}", _time.GetElapsedTime(started));
            }

            await _delay(_options.PollInterval, cancellationToken).ConfigureAwait(false);
            waited += _options.PollInterval;
        }
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._#-]{0,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex AppNamePattern();
}
