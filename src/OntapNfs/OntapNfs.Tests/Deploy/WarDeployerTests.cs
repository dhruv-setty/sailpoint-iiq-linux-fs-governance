using OntapNfs.Core.FileAccess;
using OntapNfs.Deploy;
using Xunit;

namespace OntapNfs.Tests.Deploy;

public sealed class WarDeployerTests : IDisposable
{
    private readonly TempDir _mount = new();
    private readonly TempDir _build = new();
    private readonly NfsShare _share;

    public WarDeployerTests()
    {
        _share = new NfsShare(_mount.Path, RetryPolicy.None);
    }

    public void Dispose()
    {
        _mount.Dispose();
        _build.Dispose();
    }

    private string Deployments => _mount.Combine("opt", "wildfly", "standalone", "deployments");

    private WarDeployer WildFly(Func<int, Task>? onPoll = null, int timeoutPolls = 5)
    {
        var polls = 0;
        return new WarDeployer(_share, new WarDeploymentOptions
        {
            Kind = AppServerKind.WildFly,
            DeploymentDirectory = "opt/wildfly/standalone/deployments",
            PollInterval = TimeSpan.FromMilliseconds(1),
            MarkerTimeout = TimeSpan.FromMilliseconds(timeoutPolls),
        }, async (_, _) =>
        {
            polls++;
            if (onPoll is not null)
            {
                await onPoll(polls);
            }
        });
    }

    [Theory]
    [InlineData(AppServerKind.Tomcat, "opt/tomcat/webapps", "Tomcat autoDeploy")]
    [InlineData(AppServerKind.Jetty, "opt/jetty-base/webapps", "Jetty deployment manager")]
    public async Task Tomcat_and_jetty_copy_atomically(AppServerKind kind, string dir, string scanner)
    {
        var war = Wars.Create(_build.Path);
        var deployer = new WarDeployer(_share, new WarDeploymentOptions { Kind = kind, DeploymentDirectory = dir });

        var result = await deployer.DeployAsync(war, "identityiq.war");

        Assert.Equal(DeploymentStatus.Copied, result.Status);
        Assert.Contains(scanner, result.Message, StringComparison.Ordinal);
        Assert.Equal(_share.Resolve(dir + "/identityiq.war"), result.WarPath);
        Assert.Equal(await File.ReadAllBytesAsync(war), await File.ReadAllBytesAsync(result.WarPath));
        Assert.Equal(new[] { "identityiq.war" }, Directory.GetFiles(deployer.DeploymentDirectory).Select(Path.GetFileName));
        Assert.Null(result.MarkerPath);
    }

    [Fact]
    public async Task WildFly_success_when_scanner_consumes_dodeploy_and_writes_deployed()
    {
        var war = Wars.Create(_build.Path);
        var deployer = WildFly(poll =>
        {
            var marker = Path.Combine(Deployments, "identityiq.war.dodeploy");
            Assert.True(File.Exists(marker));
            Assert.True(File.Exists(Path.Combine(Deployments, "identityiq.war")), "WAR must be in place before the marker");
            File.Delete(marker);
            File.WriteAllText(Path.Combine(Deployments, "identityiq.war.deployed"), "");
            return Task.CompletedTask;
        });

        var result = await deployer.DeployAsync(war, "identityiq");

        Assert.Equal(DeploymentStatus.Deployed, result.Status);
        Assert.EndsWith(".deployed", result.MarkerPath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WildFly_isdeploying_keeps_waiting()
    {
        var war = Wars.Create(_build.Path);
        var deployer = WildFly(poll =>
        {
            var baseName = Path.Combine(Deployments, "app.war");
            if (poll == 1)
            {
                File.Delete(baseName + ".dodeploy");
                File.WriteAllText(baseName + ".isdeploying", "");
                File.WriteAllText(baseName + ".deployed", "");
            }
            else if (poll == 2)
            {
                File.Delete(baseName + ".isdeploying");
            }

            return Task.CompletedTask;
        });

        var result = await deployer.DeployAsync(war, "app");
        Assert.Equal(DeploymentStatus.Deployed, result.Status);
    }

    [Fact]
    public async Task WildFly_failure_reports_failed_marker_content()
    {
        var war = Wars.Create(_build.Path);
        var deployer = WildFly(_ =>
        {
            File.Delete(Path.Combine(Deployments, "app.war.dodeploy"));
            File.WriteAllText(Path.Combine(Deployments, "app.war.failed"), "WFLYCTL0080: Failed services\n");
            return Task.CompletedTask;
        });

        var result = await deployer.DeployAsync(war, "app");

        Assert.Equal(DeploymentStatus.Failed, result.Status);
        Assert.Equal("WFLYCTL0080: Failed services", result.Message);
    }

    [Fact]
    public async Task WildFly_empty_failed_marker_gets_default_message()
    {
        var war = Wars.Create(_build.Path);
        var deployer = WildFly(_ =>
        {
            File.WriteAllText(Path.Combine(Deployments, "app.war.failed"), "");
            return Task.CompletedTask;
        });

        var result = await deployer.DeployAsync(war, "app");
        Assert.Equal(DeploymentStatus.Failed, result.Status);
        Assert.Contains("without detail", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WildFly_stale_markers_are_cleared_but_deployed_is_kept()
    {
        Directory.CreateDirectory(Deployments);
        var baseName = Path.Combine(Deployments, "app.war");
        File.WriteAllText(baseName + ".failed", "old failure");
        File.WriteAllText(baseName + ".undeployed", "");
        File.WriteAllText(baseName + ".pending", "");
        File.WriteAllText(baseName + ".deployed", "");
        var war = Wars.Create(_build.Path);
        var sawDeployedDuringCopy = false;

        var deployer = WildFly(_ =>
        {
            sawDeployedDuringCopy = File.Exists(baseName + ".deployed");
            File.Delete(baseName + ".dodeploy");
            return Task.CompletedTask;
        });

        var result = await deployer.DeployAsync(war, "app");

        Assert.True(sawDeployedDuringCopy, "deleting .deployed would undeploy the running application");
        Assert.Equal(DeploymentStatus.Deployed, result.Status);
        Assert.False(File.Exists(baseName + ".failed"));
        Assert.False(File.Exists(baseName + ".undeployed"));
        Assert.False(File.Exists(baseName + ".pending"));
    }

    [Fact]
    public async Task WildFly_times_out_when_scanner_is_off()
    {
        var war = Wars.Create(_build.Path);
        var result = await WildFly().DeployAsync(war, "app");

        Assert.Equal(DeploymentStatus.TimedOut, result.Status);
        Assert.Contains("never picked up", result.Message, StringComparison.Ordinal);
        Assert.EndsWith(".dodeploy", result.MarkerPath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WildFly_times_out_when_scanner_took_request_without_outcome()
    {
        var war = Wars.Create(_build.Path);
        var deployer = WildFly(_ =>
        {
            File.Delete(Path.Combine(Deployments, "app.war.dodeploy"));
            return Task.CompletedTask;
        });

        var result = await deployer.DeployAsync(war, "app");
        Assert.Equal(DeploymentStatus.TimedOut, result.Status);
        Assert.Contains("neither .deployed nor .failed", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_non_war_and_bad_names()
    {
        var deployer = WildFly();
        var notZip = Path.Combine(_build.Path, "x.war");
        await File.WriteAllTextAsync(notZip, "not a zip");
        await Assert.ThrowsAnyAsync<InvalidDataException>(() => deployer.DeployAsync(notZip, "app"));

        var noWebInf = Wars.Create(_build.Path, "static.war", withWebInf: false);
        await Assert.ThrowsAsync<InvalidDataException>(() => deployer.DeployAsync(noWebInf, "app"));
        WarDeployer.ValidateWar(noWebInf, requireWebInf: false);

        var good = Wars.Create(_build.Path);
        foreach (var bad in new[] { "../evil", "a/b", ".hidden", "a..b", "with space", "" })
        {
            await Assert.ThrowsAnyAsync<ArgumentException>(() => deployer.DeployAsync(good, bad));
        }

        Assert.False(Directory.Exists(Deployments) && Directory.GetFiles(Deployments).Length > 0);
    }

    [Fact]
    public async Task Rejects_empty_archive()
    {
        var empty = Path.Combine(_build.Path, "empty.war");
        using (System.IO.Compression.ZipFile.Open(empty, System.IO.Compression.ZipArchiveMode.Create))
        {
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => WildFly().DeployAsync(empty, "app"));
    }

    [Theory]
    [InlineData("ROOT", "ROOT")]
    [InlineData("api#v2.war", "api#v2")]
    [InlineData("identityiq-8.4.WAR", "identityiq-8.4")]
    public void Normalizes_names(string input, string expected)
        => Assert.Equal(expected, WarDeployer.NormalizeAppName(input));

    [Fact]
    public void Deployment_directory_cannot_escape_share()
        => Assert.Throws<PathTraversalException>(() => new WarDeployer(_share, new WarDeploymentOptions { Kind = AppServerKind.Tomcat, DeploymentDirectory = "../webapps" }));

    [Fact]
    public async Task Removes_only_stale_temp_files()
    {
        var deployer = new WarDeployer(_share, new WarDeploymentOptions { Kind = AppServerKind.Tomcat, DeploymentDirectory = "webapps" });
        Directory.CreateDirectory(deployer.DeploymentDirectory);
        var stale = Path.Combine(deployer.DeploymentDirectory, ".app.war.0123456789ab.tmp");
        var fresh = Path.Combine(deployer.DeploymentDirectory, ".app.war.ba9876543210.tmp");
        var war = Path.Combine(deployer.DeploymentDirectory, "app.war");
        await File.WriteAllTextAsync(stale, "x");
        await File.WriteAllTextAsync(fresh, "x");
        await File.WriteAllTextAsync(war, "x");
        File.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddHours(-2));
        File.SetLastWriteTimeUtc(war, DateTime.UtcNow.AddHours(-2));

        var removed = deployer.RemoveStaleTempFiles(TimeSpan.FromHours(1));

        Assert.Equal(new[] { ".app.war.0123456789ab.tmp" }, removed);
        Assert.True(File.Exists(fresh));
        Assert.True(File.Exists(war));
    }
}
