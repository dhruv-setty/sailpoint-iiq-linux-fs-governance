using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using OntapNfs.Ontap.Models;

namespace OntapNfs.Ontap;

/// <summary>
/// Typed client for the ONTAP REST API endpoints this module needs. Every call
/// sends HTTP Basic credentials from <see cref="OntapClientOptions"/>; asynchronous
/// operations that answer 202 Accepted are followed to completion through
/// <c>/api/cluster/jobs/{uuid}</c>.
/// </summary>
public sealed class OntapClient
{
    internal const string VolumeFields = "uuid,name,state,svm.name,svm.uuid,nas.path,nas.security_style,nas.uid,nas.gid,nas.unix_permissions,nas.export_policy.name,nas.export_policy.id";
    internal const string RuleFields = "index,clients,protocols,ro_rule,rw_rule,superuser,anonymous_user";

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly OntapClientOptions _options;
    private readonly AuthenticationHeaderValue _auth;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    /// <summary>Creates a client. The caller owns the <see cref="HttpClient"/> and its handler (TLS policy lives there).</summary>
    public OntapClient(HttpClient httpClient, OntapClientOptions options, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        _http = httpClient;
        _options = options;
        _delay = delay ?? Task.Delay;
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(options.Username + ":" + options.Password));
        _auth = new AuthenticationHeaderValue("Basic", token);
    }

    // Volumes

    /// <summary>Lists volumes, optionally filtered by SVM and name.</summary>
    public Task<IReadOnlyList<VolumeRecord>> GetVolumesAsync(string? svmName = null, string? name = null, CancellationToken cancellationToken = default)
        => GetAllAsync<VolumeRecord>("/api/storage/volumes", Query(("svm.name", svmName), ("name", name), ("fields", VolumeFields)), cancellationToken);

    /// <summary>One volume by SVM and name, or null.</summary>
    public async Task<VolumeRecord?> GetVolumeAsync(string svmName, string name, CancellationToken cancellationToken = default)
        => Single(await GetVolumesAsync(svmName, name, cancellationToken).ConfigureAwait(false), $"volume {svmName}:{name}");

    /// <summary>Assigns an export policy to a volume. Volume PATCH is asynchronous; this waits for the job.</summary>
    public Task<JobRecord?> SetVolumeExportPolicyAsync(string volumeUuid, string policyName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeUuid);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        var body = new VolumeRecord { Nas = new VolumeNas { ExportPolicy = new NamedRef { Name = policyName } } };
        return SendForJobAsync(HttpMethod.Patch, "/api/storage/volumes/" + Uri.EscapeDataString(volumeUuid), body, cancellationToken);
    }

    // Export policies and rules

    /// <summary>Lists export policies.</summary>
    public Task<IReadOnlyList<ExportPolicyRecord>> GetExportPoliciesAsync(string? svmName = null, string? name = null, CancellationToken cancellationToken = default)
        => GetAllAsync<ExportPolicyRecord>("/api/protocols/nfs/export-policies", Query(("svm.name", svmName), ("name", name), ("fields", "id,name,svm.name,svm.uuid")), cancellationToken);

    /// <summary>One export policy by SVM and name, or null.</summary>
    public async Task<ExportPolicyRecord?> GetExportPolicyAsync(string svmName, string name, CancellationToken cancellationToken = default)
        => Single(await GetExportPoliciesAsync(svmName, name, cancellationToken).ConfigureAwait(false), $"export policy {svmName}:{name}");

    /// <summary>Creates an empty export policy.</summary>
    public async Task<ExportPolicyRecord> CreateExportPolicyAsync(string svmName, string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(svmName);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var body = new ExportPolicyRecord { Name = name, Svm = new SvmRef { Name = svmName } };
        var created = await SendForRecordAsync<ExportPolicyRecord>(HttpMethod.Post, "/api/protocols/nfs/export-policies?return_records=true", body, cancellationToken).ConfigureAwait(false);
        return created ?? throw new OntapApiException(HttpStatusCode.OK, null, "export policy create returned no record");
    }

    /// <summary>Lists the rules of an export policy.</summary>
    public Task<IReadOnlyList<ExportRuleRecord>> GetExportRulesAsync(long policyId, CancellationToken cancellationToken = default)
        => GetAllAsync<ExportRuleRecord>(RulesPath(policyId), Query(("fields", RuleFields)), cancellationToken);

    /// <summary>Adds a rule to a policy. ONTAP assigns the next index when none is given.</summary>
    public async Task<ExportRuleRecord> CreateExportRuleAsync(long policyId, ExportRuleRecord rule, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var created = await SendForRecordAsync<ExportRuleRecord>(HttpMethod.Post, RulesPath(policyId) + "?return_records=true", rule, cancellationToken).ConfigureAwait(false);
        return created ?? rule;
    }

    /// <summary>Updates a rule in place.</summary>
    public Task PatchExportRuleAsync(long policyId, int index, ExportRuleRecord rule, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        return SendForJobAsync(HttpMethod.Patch, RulesPath(policyId) + "/" + index.ToString(System.Globalization.CultureInfo.InvariantCulture), rule, cancellationToken);
    }

    // UNIX users and groups

    /// <summary>Lists UNIX users on an SVM, optionally by name or UID.</summary>
    public Task<IReadOnlyList<UnixUserRecord>> GetUnixUsersAsync(string svmName, string? name = null, long? uid = null, CancellationToken cancellationToken = default)
        => GetAllAsync<UnixUserRecord>("/api/name-services/unix-users", Query(("svm.name", svmName), ("name", name), ("id", uid?.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("fields", "svm.name,svm.uuid,name,id,primary_gid,full_name")), cancellationToken);

    /// <summary>Creates a UNIX user.</summary>
    public Task CreateUnixUserAsync(UnixUserRecord user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        return SendForJobAsync(HttpMethod.Post, "/api/name-services/unix-users", user, cancellationToken);
    }

    /// <summary>Updates UID, primary GID or full name of a UNIX user.</summary>
    public Task PatchUnixUserAsync(string svmUuid, string name, UnixUserRecord changes, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(svmUuid);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(changes);
        return SendForJobAsync(HttpMethod.Patch, $"/api/name-services/unix-users/{Uri.EscapeDataString(svmUuid)}/{Uri.EscapeDataString(name)}", changes, cancellationToken);
    }

    /// <summary>Lists UNIX groups on an SVM, optionally by name or GID, with members.</summary>
    public Task<IReadOnlyList<UnixGroupRecord>> GetUnixGroupsAsync(string svmName, string? name = null, long? gid = null, CancellationToken cancellationToken = default)
        => GetAllAsync<UnixGroupRecord>("/api/name-services/unix-groups", Query(("svm.name", svmName), ("name", name), ("id", gid?.ToString(System.Globalization.CultureInfo.InvariantCulture)), ("fields", "svm.name,svm.uuid,name,id,users.name")), cancellationToken);

    /// <summary>Creates a UNIX group.</summary>
    public Task CreateUnixGroupAsync(UnixGroupRecord group, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(group);
        return SendForJobAsync(HttpMethod.Post, "/api/name-services/unix-groups", group, cancellationToken);
    }

    /// <summary>Changes the GID of a UNIX group.</summary>
    public Task PatchUnixGroupAsync(string svmUuid, string name, UnixGroupRecord changes, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(svmUuid);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(changes);
        return SendForJobAsync(HttpMethod.Patch, GroupPath(svmUuid, name), changes, cancellationToken);
    }

    /// <summary>Adds users to a UNIX group (<c>POST /api/name-services/unix-groups/{svm.uuid}/{name}/users</c>).</summary>
    public Task AddUnixGroupMembersAsync(string svmUuid, string groupName, IEnumerable<string> userNames, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(svmUuid);
        ArgumentException.ThrowIfNullOrWhiteSpace(groupName);
        ArgumentNullException.ThrowIfNull(userNames);
        var body = new RecordsResponse<UnixGroupMember> { Records = userNames.Select(n => new UnixGroupMember { Name = n }).ToList() };
        body.NumRecords = body.Records.Count;
        return SendForJobAsync(HttpMethod.Post, $"{GroupPath(svmUuid, groupName)}/users", body, cancellationToken);
    }

    /// <summary>Removes one user from a UNIX group.</summary>
    public Task RemoveUnixGroupMemberAsync(string svmUuid, string groupName, string userName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(svmUuid);
        ArgumentException.ThrowIfNullOrWhiteSpace(groupName);
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        return SendNoBodyAsync(HttpMethod.Delete, $"{GroupPath(svmUuid, groupName)}/users/{Uri.EscapeDataString(userName)}", cancellationToken);
    }

    // NFS service

    /// <summary>Lists NFS service configuration per SVM.</summary>
    public Task<IReadOnlyList<NfsServiceRecord>> GetNfsServicesAsync(string? svmName = null, CancellationToken cancellationToken = default)
        => GetAllAsync<NfsServiceRecord>("/api/protocols/nfs/services", Query(("svm.name", svmName), ("fields", "svm.name,svm.uuid,enabled,state,protocol.v3_enabled,protocol.v40_enabled")), cancellationToken);

    // Jobs

    /// <summary>Reads a job.</summary>
    public async Task<JobRecord> GetJobAsync(string uuid, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uuid);
        using var response = await SendAsync(HttpMethod.Get, "/api/cluster/jobs/" + Uri.EscapeDataString(uuid) + "?fields=uuid,state,message,code,description", null, cancellationToken).ConfigureAwait(false);
        return await ReadAsync<JobRecord>(response, cancellationToken).ConfigureAwait(false)
            ?? throw new OntapApiException(response.StatusCode, null, "empty job response");
    }

    /// <summary>Polls a job until it succeeds, fails or the timeout passes.</summary>
    /// <exception cref="OntapJobFailedException">The job ended in failure.</exception>
    /// <exception cref="TimeoutException">The job did not finish in <see cref="OntapClientOptions.JobTimeout"/>.</exception>
    public async Task<JobRecord> WaitForJobAsync(string uuid, CancellationToken cancellationToken = default)
    {
        var started = DateTime.UtcNow;
        var waited = TimeSpan.Zero;
        while (true)
        {
            var job = await GetJobAsync(uuid, cancellationToken).ConfigureAwait(false);
            switch (job.State)
            {
                case "success":
                    return job;
                case "failure":
                    throw new OntapJobFailedException(job);
            }

            if (waited >= _options.JobTimeout)
            {
                throw new TimeoutException($"ONTAP job {uuid} still '{job.State}' after {waited} (started {started:O}).");
            }

            await _delay(_options.JobPollInterval, cancellationToken).ConfigureAwait(false);
            waited += _options.JobPollInterval;
        }
    }

    // Transport

    private async Task<IReadOnlyList<T>> GetAllAsync<T>(string path, string query, CancellationToken cancellationToken)
    {
        var all = new List<T>();
        string? next = path + query;
        var pages = 0;
        while (next is not null)
        {
            if (++pages > 1000)
            {
                throw new OntapApiException(HttpStatusCode.OK, null, "pagination did not terminate for " + path);
            }

            using var response = await SendAsync(HttpMethod.Get, next, null, cancellationToken).ConfigureAwait(false);
            var page = await ReadAsync<RecordsResponse<T>>(response, cancellationToken).ConfigureAwait(false);
            if (page is null)
            {
                break;
            }

            all.AddRange(page.Records);
            next = page.Links?.Next?.Value;
        }

        return all;
    }

    private async Task<TRecord?> SendForRecordAsync<TRecord>(HttpMethod method, string path, object body, CancellationToken cancellationToken)
        where TRecord : class
    {
        using var response = await SendAsync(method, path, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            await FollowJobAsync(response, cancellationToken).ConfigureAwait(false);
            return null;
        }

        var page = await ReadAsync<RecordsResponse<TRecord>>(response, cancellationToken).ConfigureAwait(false);
        return page?.Records.FirstOrDefault();
    }

    private async Task<JobRecord?> SendForJobAsync(HttpMethod method, string path, object body, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(method, path, body, cancellationToken).ConfigureAwait(false);
        return response.StatusCode == HttpStatusCode.Accepted
            ? await FollowJobAsync(response, cancellationToken).ConfigureAwait(false)
            : null;
    }

    private async Task<JobRecord?> FollowJobAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var link = await ReadAsync<JobLinkResponse>(response, cancellationToken).ConfigureAwait(false);
        var uuid = link?.Job?.Uuid;
        return uuid is null ? null : await WaitForJobAsync(uuid, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string pathAndQuery, object? body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, new Uri(_options.BaseUri, pathAndQuery));
        request.Headers.Authorization = _auth;
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType(), options: Json);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.RequestTimeout);
        var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        using (response)
        {
            ErrorDetail? detail = null;
            try
            {
                detail = (await response.Content.ReadFromJsonAsync<ErrorResponse>(Json, cancellationToken).ConfigureAwait(false))?.Error;
            }
            catch (JsonException)
            {
                // Non JSON error body (a proxy page, for example); report the status alone.
            }

            throw new OntapApiException(response.StatusCode, detail?.Code, detail?.Message ?? response.ReasonPhrase ?? "request failed", method.Method + " " + pathAndQuery);
        }
    }

    private static async Task<T?> ReadAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength == 0)
        {
            return default;
        }

        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(text) ? default : JsonSerializer.Deserialize<T>(text, Json);
    }

    private static T? Single<T>(IReadOnlyList<T> records, string what)
        where T : class
        => records.Count switch
        {
            0 => null,
            1 => records[0],
            _ => throw new OntapApiException(HttpStatusCode.OK, null, $"{what} matched {records.Count} records"),
        };

    private async Task SendNoBodyAsync(HttpMethod method, string path, CancellationToken cancellationToken)
    {
        using var response = await SendAsync(method, path, null, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            await FollowJobAsync(response, cancellationToken).ConfigureAwait(false);
        }
    }

    private static string GroupPath(string svmUuid, string name)
        => $"/api/name-services/unix-groups/{Uri.EscapeDataString(svmUuid)}/{Uri.EscapeDataString(name)}";

    private static string RulesPath(long policyId)
        => "/api/protocols/nfs/export-policies/" + policyId.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/rules";

    internal static string Query(params (string Key, string? Value)[] pairs)
    {
        var parts = pairs.Where(p => p.Value is not null)
            .Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value!).Replace("%2C", ",", StringComparison.Ordinal));
        var joined = string.Join("&", parts);
        return joined.Length == 0 ? string.Empty : "?" + joined;
    }
}

/// <summary>An ONTAP REST call returned an error.</summary>
public class OntapApiException : Exception
{
    /// <summary>Creates the exception.</summary>
    public OntapApiException(HttpStatusCode statusCode, string? errorCode, string message, string? request = null)
        : base(request is null ? message : $"{request}: {(int)statusCode} {message}")
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }

    /// <summary>Creates the exception.</summary>
    public OntapApiException()
        : this(HttpStatusCode.InternalServerError, null, "ONTAP request failed")
    {
    }

    /// <summary>Creates the exception.</summary>
    public OntapApiException(string message)
        : this(HttpStatusCode.InternalServerError, null, message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public OntapApiException(string message, Exception innerException)
        : base(message, innerException)
    {
        StatusCode = HttpStatusCode.InternalServerError;
    }

    /// <summary>HTTP status.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>ONTAP error code, for example 1703936 or 262197.</summary>
    public string? ErrorCode { get; }
}

/// <summary>An asynchronous ONTAP job finished in the failure state.</summary>
public sealed class OntapJobFailedException : OntapApiException
{
    /// <summary>Creates the exception.</summary>
    public OntapJobFailedException(JobRecord job)
        : base(HttpStatusCode.OK, job?.Code?.ToString(System.Globalization.CultureInfo.InvariantCulture), $"job {job?.Uuid} failed: {job?.Message}")
    {
        Job = job ?? new JobRecord();
    }

    /// <summary>Creates the exception.</summary>
    public OntapJobFailedException()
        : this(new JobRecord())
    {
    }

    /// <summary>Creates the exception.</summary>
    public OntapJobFailedException(string message)
        : base(message)
    {
        Job = new JobRecord { Message = message };
    }

    /// <summary>Creates the exception.</summary>
    public OntapJobFailedException(string message, Exception innerException)
        : base(message, innerException)
    {
        Job = new JobRecord { Message = message };
    }

    /// <summary>The failed job.</summary>
    public JobRecord Job { get; }
}
