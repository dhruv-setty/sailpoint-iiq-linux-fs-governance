using System.Net;
using System.Text;
using System.Text.Json;
using OntapNfs.Ontap;
using OntapNfs.Ontap.Models;
using Xunit;

namespace OntapNfs.Tests.Ontap;

public sealed class OntapClientTests
{
    internal static readonly OntapClientOptions Options = new()
    {
        BaseUri = new Uri("https://cluster1.example.test"),
        Username = "api_user",
        Password = "not-a-real-password",
        JobPollInterval = TimeSpan.FromMilliseconds(1),
        JobTimeout = TimeSpan.FromMilliseconds(5),
    };

    internal static (OntapClient Client, FakeOntapHandler Handler, List<TimeSpan> Delays) Create()
    {
        var handler = new FakeOntapHandler();
        var delays = new List<TimeSpan>();
        var client = new OntapClient(new HttpClient(handler), Options, (d, _) =>
        {
            delays.Add(d);
            return Task.CompletedTask;
        });
        return (client, handler, delays);
    }

    [Fact]
    public async Task Sends_basic_auth_and_parses_volumes()
    {
        var (client, handler, _) = Create();
        handler.On("GET", "/api/storage/volumes", HttpStatusCode.OK, """
            {"records":[{"uuid":"v-1","name":"vol1","state":"online","svm":{"name":"svm1","uuid":"s-1"},
              "nas":{"path":"/vol1","security_style":"unix","uid":0,"gid":4300,"unix_permissions":1533,
                     "export_policy":{"name":"app_nfs","id":42}}}],"num_records":1}
            """);

        var v = await client.GetVolumeAsync("svm1", "vol1");

        Assert.NotNull(v);
        Assert.Equal("v-1", v!.Uuid);
        Assert.Equal("/vol1", v.Nas!.Path);
        Assert.Equal(4300, v.Nas.Gid);
        Assert.Equal("app_nfs", v.Nas.ExportPolicy!.Name);
        Assert.Equal(42, v.Nas.ExportPolicy.Id);
        var req = Assert.Single(handler.Requests);
        var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("api_user:not-a-real-password"));
        Assert.Equal(expected, req.Authorization);
        Assert.Contains("svm.name=svm1", req.Query, StringComparison.Ordinal);
        Assert.Contains("name=vol1", req.Query, StringComparison.Ordinal);
        Assert.Contains("fields=uuid,name,state", req.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Follows_pagination_links()
    {
        var (client, handler, _) = Create();
        handler.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK,
            """{"records":[{"name":"a","id":1,"primary_gid":1}],"num_records":1,"_links":{"next":{"href":"/api/name-services/unix-users?start.name=a"}}}""");
        handler.On("GET", "/api/name-services/unix-users", HttpStatusCode.OK,
            """{"records":[{"name":"b","id":2,"primary_gid":2}],"num_records":1}""");

        var users = await client.GetUnixUsersAsync("svm1");

        Assert.Equal(new[] { "a", "b" }, users.Select(u => u.Name));
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("?start.name=a", handler.Requests[1].Query);
    }

    [Fact]
    public async Task Single_lookup_returns_null_or_throws_on_ambiguity()
    {
        var (client, handler, _) = Create();
        handler.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, """{"records":[],"num_records":0}""");
        handler.On("GET", "/api/protocols/nfs/export-policies", HttpStatusCode.OK, """{"records":[{"id":1,"name":"p"},{"id":2,"name":"p"}],"num_records":2}""");

        Assert.Null(await client.GetExportPolicyAsync("svm1", "p"));
        await Assert.ThrowsAsync<OntapApiException>(() => client.GetExportPolicyAsync("svm1", "p"));
    }

    [Fact]
    public async Task Error_body_becomes_typed_exception()
    {
        var (client, handler, _) = Create();
        handler.On("POST", "/api/name-services/unix-users", HttpStatusCode.Conflict,
            """{"error":{"message":"duplicate entry","code":"23724066","target":"name"}}""");

        var ex = await Assert.ThrowsAsync<OntapApiException>(() => client.CreateUnixUserAsync(new UnixUserRecord { Name = "x", Id = 5, PrimaryGid = 5 }));

        Assert.Equal(HttpStatusCode.Conflict, ex.StatusCode);
        Assert.Equal("23724066", ex.ErrorCode);
        Assert.Contains("duplicate entry", ex.Message, StringComparison.Ordinal);
        Assert.Contains("POST /api/name-services/unix-users", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Non_json_error_body_still_reports_status()
    {
        var (client, handler, _) = Create();
        handler.On("GET", "/api/protocols/nfs/services", _ => new HttpResponseMessage(HttpStatusCode.BadGateway) { Content = new StringContent("<html>proxy</html>") });

        var ex = await Assert.ThrowsAsync<OntapApiException>(() => client.GetNfsServicesAsync("svm1"));
        Assert.Equal(HttpStatusCode.BadGateway, ex.StatusCode);
        Assert.Null(ex.ErrorCode);
    }

    [Fact]
    public async Task Async_patch_polls_job_until_success()
    {
        var (client, handler, delays) = Create();
        handler.On("PATCH", "/api/storage/volumes/v-1", HttpStatusCode.Accepted, """{"job":{"uuid":"j-1"}}""");
        handler.On("GET", "/api/cluster/jobs/j-1", HttpStatusCode.OK, """{"uuid":"j-1","state":"running"}""");
        handler.On("GET", "/api/cluster/jobs/j-1", HttpStatusCode.OK, """{"uuid":"j-1","state":"success","message":"success"}""");

        var job = await client.SetVolumeExportPolicyAsync("v-1", "app_nfs");

        Assert.Equal("success", job!.State);
        Assert.Single(delays);
        var patch = handler.Requests[0];
        using var doc = JsonDocument.Parse(patch.Body!);
        Assert.Equal("app_nfs", doc.RootElement.GetProperty("nas").GetProperty("export_policy").GetProperty("name").GetString());
        Assert.False(doc.RootElement.TryGetProperty("uuid", out _), "null fields must not be sent");
    }

    [Fact]
    public async Task Failed_job_throws_with_job_detail()
    {
        var (client, handler, _) = Create();
        handler.On("PATCH", "/api/storage/volumes/v-1", HttpStatusCode.Accepted, """{"job":{"uuid":"j-2"}}""");
        handler.On("GET", "/api/cluster/jobs/j-2", HttpStatusCode.OK, """{"uuid":"j-2","state":"failure","message":"policy not found","code":917927}""");

        var ex = await Assert.ThrowsAsync<OntapJobFailedException>(() => client.SetVolumeExportPolicyAsync("v-1", "nope"));
        Assert.Equal("917927", ex.ErrorCode);
        Assert.Equal("policy not found", ex.Job.Message);
    }

    [Fact]
    public async Task Job_that_never_finishes_times_out()
    {
        var (client, handler, delays) = Create();
        handler.On("GET", "/api/cluster/jobs/j-3", HttpStatusCode.OK, """{"uuid":"j-3","state":"queued"}""");

        await Assert.ThrowsAsync<TimeoutException>(() => client.WaitForJobAsync("j-3"));
        Assert.Equal(5, delays.Count);
    }

    [Fact]
    public async Task Creates_policy_and_rule_with_return_records()
    {
        var (client, handler, _) = Create();
        handler.On("POST", "/api/protocols/nfs/export-policies", HttpStatusCode.Created, """{"records":[{"id":77,"name":"app_nfs","svm":{"name":"svm1"}}],"num_records":1}""");
        handler.On("POST", "/api/protocols/nfs/export-policies/77/rules", HttpStatusCode.Created, """{"records":[{"index":1,"clients":[{"match":"10.20.0.0/16"}]}],"num_records":1}""");

        var policy = await client.CreateExportPolicyAsync("svm1", "app_nfs");
        var rule = await client.CreateExportRuleAsync(77, new ExportRuleRecord { Clients = new() { new ExportClientRecord { Match = "10.20.0.0/16" } } });

        Assert.Equal(77, policy.Id);
        Assert.Equal(1, rule.Index);
        Assert.Equal("?return_records=true", handler.Requests[0].Query);
        using var body = JsonDocument.Parse(handler.Requests[0].Body!);
        Assert.Equal("svm1", body.RootElement.GetProperty("svm").GetProperty("name").GetString());
    }

    [Fact]
    public async Task Rule_patch_uses_index_url_and_users_groups_use_svm_uuid()
    {
        var (client, handler, _) = Create();
        handler.On("PATCH", "/api/protocols/nfs/export-policies/77/rules/3", HttpStatusCode.OK, "{}");
        handler.On("PATCH", "/api/name-services/unix-users/s-1/svc_tomcat", HttpStatusCode.OK, "");
        handler.On("PATCH", "/api/name-services/unix-groups/s-1/app_deploy", HttpStatusCode.OK, "");
        handler.On("POST", "/api/name-services/unix-groups", HttpStatusCode.Created, "");

        await client.PatchExportRuleAsync(77, 3, new ExportRuleRecord { RwRule = new() { "sys" } });
        await client.PatchUnixUserAsync("s-1", "svc_tomcat", new UnixUserRecord { PrimaryGid = 1201 });
        await client.PatchUnixGroupAsync("s-1", "app_deploy", new UnixGroupRecord { Id = 4300 });
        await client.CreateUnixGroupAsync(new UnixGroupRecord { Name = "g", Id = 9 });

        Assert.Equal(4, handler.Writes.Count());
        Assert.Contains("\"rw_rule\":[\"sys\"]", handler.Requests[0].Body!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reads_groups_rules_and_nfs_services()
    {
        var (client, handler, _) = Create();
        handler.On("GET", "/api/name-services/unix-groups", HttpStatusCode.OK, """{"records":[{"name":"app_deploy","id":4300,"users":[{"name":"svc_tomcat"}]}]}""");
        handler.On("GET", "/api/protocols/nfs/export-policies/5/rules", HttpStatusCode.OK, """{"records":[{"index":1,"ro_rule":["sys"],"rw_rule":["sys"],"superuser":["none"],"anonymous_user":"65534","protocols":["nfs3"],"clients":[{"match":"0.0.0.0/0"}]}]}""");
        handler.On("GET", "/api/protocols/nfs/services", HttpStatusCode.OK, """{"records":[{"svm":{"name":"svm1"},"enabled":true,"state":"online","protocol":{"v3_enabled":true,"v40_enabled":false}}]}""");

        var groups = await client.GetUnixGroupsAsync("svm1", gid: 4300);
        var rules = await client.GetExportRulesAsync(5);
        var nfs = await client.GetNfsServicesAsync("svm1");

        Assert.Equal("svc_tomcat", groups[0].Users![0].Name);
        Assert.Contains("id=4300", handler.Requests[0].Query, StringComparison.Ordinal);
        Assert.Equal("65534", rules[0].AnonymousUser);
        Assert.True(nfs[0].Protocol!.V3Enabled);
        Assert.False(nfs[0].Protocol!.V40Enabled);
        Assert.Equal("online", nfs[0].State);
    }

    [Fact]
    public void Query_escapes_values_but_keeps_field_commas()
    {
        Assert.Equal(string.Empty, OntapClient.Query(("a", null)));
        Assert.Equal("?name=a%20b&fields=x,y", OntapClient.Query(("name", "a b"), ("fields", "x,y")));
    }

    [Fact]
    public void Options_from_environment()
    {
        var env = new Dictionary<string, string?>
        {
            [OntapClientOptions.BaseUrlVariable] = "https://cluster1.example.test",
            [OntapClientOptions.UsernameVariable] = "api_user",
            [OntapClientOptions.PasswordVariable] = "pw",
        };
        var o = OntapClientOptions.FromEnvironment(k => env.GetValueOrDefault(k));
        Assert.Equal("api_user", o.Username);
        Assert.DoesNotContain("pw", o.ToString(), StringComparison.Ordinal);

        env[OntapClientOptions.BaseUrlVariable] = "http://insecure.example.test";
        Assert.Throws<InvalidOperationException>(() => OntapClientOptions.FromEnvironment(k => env.GetValueOrDefault(k)));
        env[OntapClientOptions.BaseUrlVariable] = "https://cluster1.example.test";
        env[OntapClientOptions.PasswordVariable] = " ";
        Assert.Throws<InvalidOperationException>(() => OntapClientOptions.FromEnvironment(k => env.GetValueOrDefault(k)));
    }

    [Fact]
    public void Exception_constructors()
    {
        Assert.Equal(HttpStatusCode.InternalServerError, new OntapApiException().StatusCode);
        Assert.Equal("m", new OntapApiException("m").Message);
        Assert.NotNull(new OntapApiException("m", new InvalidOperationException()).InnerException);
        Assert.NotNull(new OntapJobFailedException().Job);
        Assert.Equal("m", new OntapJobFailedException("m").Job.Message);
        Assert.NotNull(new OntapJobFailedException("m", new InvalidOperationException()).InnerException);
    }
}
