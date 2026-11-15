using System.Net;
using OntapNfs.Core.Posix;
using Xunit;
using C = OntapNfs.Core.Posix.ServiceAccountValidator.Codes;

namespace OntapNfs.Tests.Core;

public sealed class ServiceAccountValidatorTests
{
    private static readonly NfsClient Host = new(IPAddress.Parse("10.20.1.15"), "app01.prod.example.com");

    private static readonly UnixUser Tomcat = new("svc_tomcat", 1201, 1201, "Tomcat service");

    private static readonly List<UnixGroup> Groups = new()
    {
        new UnixGroup("svc_tomcat", 1201),
        new UnixGroup("app_deploy", 4300, new[] { "svc_tomcat" }),
    };

    private static readonly ExportPolicy RwPolicy = new("app_nfs", new[] { ExportRule.ForSys(1, "10.20.0.0/16", readWrite: true) });

    private static readonly PosixOwnership DeployDir = new(0, 4300, (UnixFileMode)Convert.ToInt32("2775", 8));

    private static ValidationReport Run(ServiceAccountSpec spec, IReadOnlyCollection<UnixUser>? users = null, IReadOnlyCollection<UnixGroup>? groups = null, ExportPolicy? policy = null)
        => ServiceAccountValidator.Validate(spec, users ?? new[] { Tomcat }, groups ?? Groups, policy ?? RwPolicy);

    [Fact]
    public void Valid_account_with_group_write_on_deploy_dir()
    {
        var r = Run(new ServiceAccountSpec("svc_tomcat", Host, RequiresWrite: true, DeployDir));
        Assert.True(r.IsValid, string.Join("; ", r.Issues));
        Assert.Empty(r.Issues);
        Assert.Equal(ExportAccess.ReadWrite, r.Decision!.Access);
        Assert.Equal(1201, r.Decision.EffectiveUid);
    }

    [Fact]
    public void Unknown_user()
    {
        var r = Run(new ServiceAccountSpec("svc_missing", Host, true));
        Assert.False(r.IsValid);
        Assert.True(r.Has(C.UserNotFound));
        Assert.Null(r.Decision);
    }

    [Theory]
    [InlineData(65534)]
    [InlineData(65535)]
    [InlineData(-1)]
    public void Reserved_uid(long uid)
    {
        var r = Run(new ServiceAccountSpec("svc_tomcat", Host, false), new[] { Tomcat with { Uid = uid } });
        Assert.True(r.Has(C.ReservedUid));
    }

    [Fact]
    public void Duplicate_uid_and_gid()
    {
        var users = new[] { Tomcat, new UnixUser("legacy_app", 1201, 1201) };
        var groups = Groups.Append(new UnixGroup("tomcat_old", 1201)).ToList();
        var r = Run(new ServiceAccountSpec("svc_tomcat", Host, false), users, groups);
        Assert.True(r.Has(C.DuplicateUid));
        Assert.True(r.Has(C.DuplicateGid));
        Assert.False(r.IsValid);
    }

    [Fact]
    public void Missing_primary_group()
    {
        var r = Run(new ServiceAccountSpec("svc_tomcat", Host, false), groups: new[] { new UnixGroup("other", 9) });
        Assert.True(r.Has(C.PrimaryGroupMissing));
    }

    [Fact]
    public void Read_only_export_when_write_needed()
    {
        var ro = new ExportPolicy("ro", new[] { ExportRule.ForSys(1, "0.0.0.0/0", readWrite: false) });
        var r = Run(new ServiceAccountSpec("svc_tomcat", Host, RequiresWrite: true), policy: ro);
        Assert.True(r.Has(C.WriteNotAllowed));
        Assert.True(Run(new ServiceAccountSpec("svc_tomcat", Host, RequiresWrite: false), policy: ro).IsValid);
    }

    [Fact]
    public void Export_denies_client()
    {
        var r = Run(new ServiceAccountSpec("svc_tomcat", new NfsClient(IPAddress.Parse("172.16.0.1")), false));
        Assert.True(r.Has(C.ExportDenied));
        Assert.Equal(ExportAccess.None, r.Decision!.Access);
    }

    [Fact]
    public void Root_account_is_squashed_and_cannot_write_root_owned_dir()
    {
        var root = new UnixUser("root", 0, 0);
        var groups = new[] { new UnixGroup("root", 0) };
        var dir = new PosixOwnership(0, 0, (UnixFileMode)Convert.ToInt32("0755", 8));
        var r = Run(new ServiceAccountSpec("root", Host, true, dir), new[] { root }, groups);
        Assert.True(r.Has(C.RunsAsRoot));
        Assert.True(r.Has(C.RootSquashed));
        Assert.True(r.Has(C.DirectoryNotWritable));
        Assert.Equal(65534, r.Decision!.EffectiveUid);
    }

    [Fact]
    public void Anonymous_mapping_is_an_error_when_writing_and_anon_zero_is_flagged()
    {
        var anon = new ExportPolicy("p", new[]
        {
            new ExportRule(1, new[] { "0.0.0.0/0" }, new HashSet<SecurityFlavor> { SecurityFlavor.None },
                new HashSet<SecurityFlavor> { SecurityFlavor.None }, new HashSet<SecurityFlavor> { SecurityFlavor.None }, 0,
                new HashSet<NfsProtocol> { NfsProtocol.Any }),
        });
        var w = Run(new ServiceAccountSpec("svc_tomcat", Host, true), policy: anon);
        Assert.True(w.Has(C.MappedToAnonymous));
        Assert.True(w.Has(C.AnonIsRoot));
        Assert.False(w.IsValid);

        var anon65534 = anon with { Rules = new[] { anon.Rules[0] with { AnonUid = 65534 } } };
        var ro = Run(new ServiceAccountSpec("svc_tomcat", Host, false), policy: anon65534);
        Assert.True(ro.Has(C.MappedToAnonymous));
        Assert.True(ro.IsValid);
    }

    [Fact]
    public void Auth_sys_group_limit_and_truncated_membership()
    {
        var many = Enumerable.Range(0, 17).Select(i => new UnixGroup("g" + i, 5000 + i, new[] { "svc_tomcat" }))
            .Append(new UnixGroup("svc_tomcat", 1201))
            .Append(new UnixGroup("deployers", 6000, new[] { "svc_tomcat" }))
            .ToList();
        var dir = new PosixOwnership(0, 6000, (UnixFileMode)Convert.ToInt32("0775", 8));
        var r = Run(new ServiceAccountSpec("svc_tomcat", Host, true, dir), groups: many);
        Assert.True(r.Has(C.TooManyGroups));

        // The deployers group is the 18th; AUTH_SYS only carries 16, so the write is refused.
        Assert.True(r.Has(C.DirectoryNotWritable));
    }

    [Fact]
    public void Directory_not_readable()
    {
        var dir = new PosixOwnership(0, 0, (UnixFileMode)Convert.ToInt32("0700", 8));
        var r = Run(new ServiceAccountSpec("svc_tomcat", Host, false, dir));
        Assert.True(r.Has(C.DirectoryNotReadable));
        Assert.Contains("mode 700", r.Issues.Single().Message, StringComparison.Ordinal);
    }
}
