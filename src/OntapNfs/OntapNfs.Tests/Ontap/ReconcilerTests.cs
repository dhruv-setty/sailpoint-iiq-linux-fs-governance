using System.Net;
using System.Text.Json;
using OntapNfs.Core.Posix;
using OntapNfs.Ontap;
using OntapNfs.Ontap.Models;
using Xunit;

namespace OntapNfs.Tests.Ontap;

public sealed class ReconcilerTests
{
    private const string Policy77 = """{"records":[{"id":77,"name":"app_nfs","svm":{"name":"svm1","uuid":"s-1"}}],"num_records":1}""";
    private const string Empty = """{"records":[],"num_records":0}""";

    private static readonly ExportRule Desired = ExportRule.ForSys(1, "10.20.0.0/16", readWrite: true);

    private static (OntapNfsReconciler R, FakeOntapHandler H) Create()
    {
        var (client, handler, _) = OntapClientTests.Create();
        return (new OntapNfsReconciler(client), handler);
    }

    [Fact]
    public async Task Rule_unchanged_sends_no_writes()
    {
        var (r, h) = Create();
        h.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, Policy77);
        h.On("GET", "/api/protocols/nfs/export-policies/77/rules", HttpStatusCode.OK,
            """{"records":[{"index":4,"clients":[{"match":"10.20.0.0/16"}],"protocols":["nfs3"],"ro_rule":["sys"],"rw_rule":["sys"],"superuser":["none"],"anonymous_user":"65534"}]}""");

        var result = await r.EnsureExportRuleAsync("svm1", "app_nfs", Desired);

        Assert.Equal(EnsureAction.Unchanged, result.Action);
        Assert.Empty(result.Changes);
        Assert.Empty(h.Writes);
    }

    [Fact]
    public async Task Rule_drift_is_patched_by_existing_index()
    {
        var (r, h) = Create();
        h.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, Policy77);
        h.On("GET", "/api/protocols/nfs/export-policies/77/rules", HttpStatusCode.OK,
            """{"records":[{"index":4,"clients":[{"match":"10.20.0.0/16"}],"protocols":["any"],"ro_rule":["sys"],"rw_rule":["never"],"superuser":["sys"],"anonymous_user":"0"}]}""");
        h.On("PATCH", "/api/protocols/nfs/export-policies/77/rules/4", HttpStatusCode.OK, "{}");

        var result = await r.EnsureExportRuleAsync("svm1", "app_nfs", Desired);

        Assert.Equal(EnsureAction.Updated, result.Action);
        Assert.Equal(4, result.Changes.Count);
        Assert.Contains(result.Changes, c => c.StartsWith("rw_rule [never] -> [sys]", StringComparison.Ordinal));
        Assert.Contains(result.Changes, c => c.StartsWith("anonymous_user 0 -> 65534", StringComparison.Ordinal));
        var patch = Assert.Single(h.Writes);
        using var doc = JsonDocument.Parse(patch.Body!);
        Assert.False(doc.RootElement.TryGetProperty("clients", out _));
        Assert.False(doc.RootElement.TryGetProperty("index", out _));
        Assert.Equal("65534", doc.RootElement.GetProperty("anonymous_user").GetString());
    }

    [Fact]
    public async Task Missing_policy_and_rule_are_created()
    {
        var (r, h) = Create();
        h.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, Empty);
        h.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, Policy77);
        h.On("POST", "/api/protocols/nfs/export-policies", HttpStatusCode.Created, """{"records":[{"name":"app_nfs"}]}""");
        h.On("GET", "/api/protocols/nfs/export-policies/77/rules", HttpStatusCode.OK, """{"records":[{"index":1,"clients":[{"match":"0.0.0.0/0"}],"ro_rule":["sys"],"rw_rule":["never"],"superuser":["none"]}]}""");
        h.On("POST", "/api/protocols/nfs/export-policies/77/rules", HttpStatusCode.Created, Empty);

        var result = await r.EnsureExportRuleAsync("svm1", "app_nfs", Desired);

        Assert.Equal(EnsureAction.Created, result.Action);
        Assert.Equal(new[] { "POST", "POST" }, h.Writes.Select(w => w.Method));
        using var body = JsonDocument.Parse(h.Writes.Last().Body!);
        Assert.False(body.RootElement.TryGetProperty("index", out _), "index 1 is taken, so ONTAP assigns one");
        Assert.Equal("10.20.0.0/16", body.RootElement.GetProperty("clients")[0].GetProperty("match").GetString());
    }

    [Fact]
    public async Task Policy_ensure_is_idempotent()
    {
        var (r, h) = Create();
        h.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, Policy77);
        var (policy, result) = await r.EnsureExportPolicyAsync("svm1", "app_nfs");
        Assert.Equal(77, policy.Id);
        Assert.Equal(EnsureAction.Unchanged, result.Action);
        Assert.Empty(h.Writes);
    }

    [Fact]
    public async Task Unix_user_created_updated_unchanged()
    {
        var desired = new UnixUser("svc_tomcat", 1201, 1201, "Tomcat service");

        var (r1, h1) = Create();
        h1.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK, Empty);
        h1.On("POST", "/api/name-services/unix-users", HttpStatusCode.Created, "");
        Assert.Equal(EnsureAction.Created, (await r1.EnsureUnixUserAsync("svm1", desired)).Action);
        using (var body = JsonDocument.Parse(h1.Writes.Single().Body!))
        {
            Assert.Equal(1201, body.RootElement.GetProperty("id").GetInt64());
            Assert.Equal("svm1", body.RootElement.GetProperty("svm").GetProperty("name").GetString());
        }

        var (r2, h2) = Create();
        h2.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK, Empty);
        h2.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK, """{"records":[{"svm":{"uuid":"s-1","name":"svm1"},"name":"svc_tomcat","id":1200,"primary_gid":100,"full_name":"old"}]}""");
        h2.On("PATCH", "/api/name-services/unix-users/s-1/svc_tomcat", HttpStatusCode.OK, "");
        var updated = await r2.EnsureUnixUserAsync("svm1", desired);
        Assert.Equal(EnsureAction.Updated, updated.Action);
        Assert.Equal(3, updated.Changes.Count);

        var (r3, h3) = Create();
        h3.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK, """{"records":[{"svm":{"uuid":"s-1"},"name":"svc_tomcat","id":1201,"primary_gid":1201,"full_name":"Tomcat service"}]}""");
        Assert.Equal(EnsureAction.Unchanged, (await r3.EnsureUnixUserAsync("svm1", desired)).Action);
        Assert.Empty(h3.Writes);
    }

    [Fact]
    public async Task Unix_user_refuses_uid_held_by_another_and_reserved_uids()
    {
        var (r, h) = Create();
        h.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK, """{"records":[{"name":"legacy","id":1201,"primary_gid":1}]}""");
        await Assert.ThrowsAsync<EnsureConflictException>(() => r.EnsureUnixUserAsync("svm1", new UnixUser("svc_tomcat", 1201, 1201)));
        await Assert.ThrowsAsync<EnsureConflictException>(() => r.EnsureUnixUserAsync("svm1", new UnixUser("x", 0, 0)));
        await Assert.ThrowsAsync<EnsureConflictException>(() => r.EnsureUnixUserAsync("svm1", new UnixUser("x", 65534, 1)));
        Assert.Empty(h.Writes);
    }

    [Fact]
    public async Task Unix_group_paths()
    {
        var (r1, h1) = Create();
        h1.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, Empty);
        h1.On("POST", "/api/name-services/unix-groups", HttpStatusCode.Created, "");
        Assert.Equal(EnsureAction.Created, (await r1.EnsureUnixGroupAsync("svm1", "app_deploy", 4300)).Action);

        var (r2, h2) = Create();
        h2.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, Empty);
        h2.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, """{"records":[{"svm":{"uuid":"s-1"},"name":"app_deploy","id":4299}]}""");
        h2.On("PATCH", "/api/name-services/unix-groups/s-1/app_deploy", HttpStatusCode.OK, "");
        Assert.Equal(EnsureAction.Updated, (await r2.EnsureUnixGroupAsync("svm1", "app_deploy", 4300)).Action);

        var (r3, h3) = Create();
        h3.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, """{"records":[{"name":"app_deploy","id":4300}]}""");
        Assert.Equal(EnsureAction.Unchanged, (await r3.EnsureUnixGroupAsync("svm1", "app_deploy", 4300)).Action);
        Assert.Empty(h3.Writes);

        var (r4, h4) = Create();
        h4.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, """{"records":[{"name":"finance","id":4300}]}""");
        await Assert.ThrowsAsync<EnsureConflictException>(() => r4.EnsureUnixGroupAsync("svm1", "app_deploy", 4300));
        Assert.Empty(h4.Writes);
    }

    [Fact]
    public async Task Group_members_removed_before_added_and_unchanged_when_equal()
    {
        var (r, h) = Create();
        h.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK,
            """{"records":[{"svm":{"uuid":"s-1"},"name":"fs_fin_rw","id":4101,"users":[{"name":"alice"},{"name":"mallory"}]}]}""");
        h.On("DELETE", "/api/name-services/unix-groups/s-1/fs_fin_rw/users/mallory", HttpStatusCode.OK, "");
        h.On("POST", "/api/name-services/unix-groups/s-1/fs_fin_rw/users", HttpStatusCode.Created, "");

        var result = await r.EnsureUnixGroupMembersAsync("svm1", "fs_fin_rw", new[] { "alice", "bob" }, removeOthers: true);

        Assert.Equal(EnsureAction.Updated, result.Action);
        Assert.Equal(new[] { "- mallory", "+ bob" }, result.Changes);
        Assert.Equal(new[] { "DELETE", "POST" }, h.Writes.Select(w => w.Method));
        using var body = JsonDocument.Parse(h.Writes.Last().Body!);
        Assert.Equal("bob", body.RootElement.GetProperty("records")[0].GetProperty("name").GetString());

        var keep = await r.EnsureUnixGroupMembersAsync("svm1", "fs_fin_rw", new[] { "alice" });
        Assert.Equal(EnsureAction.Unchanged, keep.Action);
    }

    [Fact]
    public async Task Group_members_for_missing_group_is_a_conflict()
    {
        var (r, h) = Create();
        h.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, Empty);
        await Assert.ThrowsAsync<EnsureConflictException>(() => r.EnsureUnixGroupMembersAsync("svm1", "nope", new[] { "a" }));
    }

    [Fact]
    public async Task Patch_without_svm_uuid_is_refused()
    {
        var (r, h) = Create();
        h.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, Empty);
        h.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, """{"records":[{"name":"g","id":1}]}""");
        await Assert.ThrowsAsync<OntapApiException>(() => r.EnsureUnixGroupAsync("svm1", "g", 2));
    }

    [Fact]
    public async Task Volume_export_policy_paths()
    {
        var (r, h) = Create();
        h.On("GET", "/api/storage/volumes", HttpStatusCode.OK, """{"records":[{"uuid":"v-1","name":"vol1","nas":{"export_policy":{"name":"default"}}}]}""");
        h.On("PATCH", "/api/storage/volumes/v-1", HttpStatusCode.Accepted, """{"job":{"uuid":"j-1"}}""");
        h.On("GET", "/api/cluster/jobs/j-1", HttpStatusCode.OK, """{"uuid":"j-1","state":"success"}""");

        var result = await r.EnsureVolumeExportPolicyAsync("svm1", "vol1", "app_nfs");
        Assert.Equal(EnsureAction.Updated, result.Action);
        Assert.Equal("export policy default -> app_nfs", result.Changes.Single());

        var (r2, h2) = Create();
        h2.On("GET", "/api/storage/volumes", HttpStatusCode.OK, """{"records":[{"uuid":"v-1","name":"vol1","nas":{"export_policy":{"name":"app_nfs"}}}]}""");
        Assert.Equal(EnsureAction.Unchanged, (await r2.EnsureVolumeExportPolicyAsync("svm1", "vol1", "app_nfs")).Action);

        var (r3, h3) = Create();
        h3.On("GET", "/api/storage/volumes", HttpStatusCode.OK, Empty);
        await Assert.ThrowsAsync<EnsureConflictException>(() => r3.EnsureVolumeExportPolicyAsync("svm1", "vol1", "app_nfs"));
    }

    [Fact]
    public async Task Validates_service_account_against_live_state()
    {
        var (r, h) = Create();
        h.On("GET", "/api/protocols/nfs/services", HttpStatusCode.OK, """{"records":[{"enabled":true,"protocol":{"v3_enabled":true}}]}""");
        h.On("GET", "/api/storage/volumes", HttpStatusCode.OK, """{"records":[{"uuid":"v-1","name":"vol1","nas":{"uid":0,"gid":4300,"unix_permissions":1533,"export_policy":{"name":"app_nfs"}}}]}""");
        h.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, Policy77);
        h.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK, """{"records":[{"name":"svc_tomcat","id":1201,"primary_gid":1201},{"name":"anon_named","id":65534,"primary_gid":65534}]}""");
        h.On("GET", "/api/protocols/nfs/export-policies/77/rules", HttpStatusCode.OK,
            """{"records":[{"index":1,"clients":[{"match":"10.20.0.0/16"}],"protocols":["nfs3"],"ro_rule":["sys"],"rw_rule":["sys"],"superuser":["none"],"anonymous_user":"anon_named"}]}""");
        h.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, """{"records":[{"name":"svc_tomcat","id":1201},{"name":"app_deploy","id":4300,"users":[{"name":"svc_tomcat"}]}]}""");

        var spec = new ServiceAccountSpec("svc_tomcat", new NfsClient(IPAddress.Parse("10.20.1.15")), RequiresWrite: true);
        var report = await r.ValidateServiceAccountAsync("svm1", "vol1", spec);

        Assert.True(report.IsValid, string.Join("; ", report.Issues));
        Assert.Equal(ExportAccess.ReadWrite, report.Decision!.Access);
    }

    [Fact]
    public async Task Validation_flags_disabled_nfsv3_and_unexported_volume()
    {
        var (r, h) = Create();
        h.On("GET", "/api/protocols/nfs/services", HttpStatusCode.OK, """{"records":[{"enabled":true,"protocol":{"v3_enabled":false}}]}""");
        h.On("GET", "/api/storage/volumes", HttpStatusCode.OK, Empty);

        var report = await r.ValidateServiceAccountAsync("svm1", "vol1", new ServiceAccountSpec("svc", new NfsClient(IPAddress.Loopback), false));

        Assert.True(report.Has("NFSV3_DISABLED"));
        Assert.True(report.Has("VOLUME_NOT_EXPORTED"));
        Assert.False(report.IsValid);
    }

    [Fact]
    public async Task Read_policy_returns_null_when_absent()
    {
        var (r, h) = Create();
        h.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, Empty);
        Assert.Null(await r.ReadExportPolicyAsync("svm1", "missing"));
    }

    [Fact]
    public void Mapper_round_trips_and_rejects_unknown_values()
    {
        var record = ExportRuleMapper.ToRecord(Desired, includeIndex: true);
        Assert.Equal(1, record.Index);
        Assert.Equal(new[] { "nfs3" }, record.Protocols);
        Assert.Equal(new[] { "none" }, record.Superuser);
        Assert.True(ExportRuleMapper.ToCore(record).SameEffectAs(Desired));

        Assert.Throws<FormatException>(() => ExportRuleMapper.ToCore(new ExportRuleRecord { RoRule = new() { "kerberos9" } }));
        Assert.Throws<FormatException>(() => ExportRuleMapper.ToCore(new ExportRuleRecord { AnonymousUser = "nobody" }));
        Assert.Equal(99, ExportRuleMapper.ToCore(new ExportRuleRecord { AnonymousUser = "nobody" }, _ => 99).AnonUid);

        var noProtocols = ExportRuleMapper.ToCore(new ExportRuleRecord());
        Assert.True(noProtocols.AppliesTo(NfsProtocol.Nfs3));
        Assert.Equal(65534, noProtocols.AnonUid);
        var cifsOnly = ExportRuleMapper.ToCore(new ExportRuleRecord { Protocols = new() { "cifs" } });
        Assert.False(cifsOnly.AppliesTo(NfsProtocol.Nfs3));
    }

    [Fact]
    public void Exception_constructors()
    {
        Assert.NotNull(new EnsureConflictException().Message);
        Assert.NotNull(new EnsureConflictException("m", new InvalidOperationException()).InnerException);
    }
}
