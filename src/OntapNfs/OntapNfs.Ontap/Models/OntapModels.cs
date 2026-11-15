using System.Text.Json.Serialization;

#pragma warning disable CA2227 // Collection setters are required for System.Text.Json DTOs.
#pragma warning disable CA1002 // List<T> keeps the DTOs simple for serialisation.

namespace OntapNfs.Ontap.Models;

/// <summary>ONTAP collection response: <c>{"records": [...], "num_records": n}</c>.</summary>
/// <typeparam name="T">Record type.</typeparam>
public sealed class RecordsResponse<T>
{
    /// <summary>Records.</summary>
    [JsonPropertyName("records")]
    public List<T> Records { get; set; } = new();

    /// <summary>Count reported by the server.</summary>
    [JsonPropertyName("num_records")]
    public int NumRecords { get; set; }

    /// <summary>HAL links; <c>next</c> is present when more pages follow.</summary>
    [JsonPropertyName("_links")]
    public PageLinks? Links { get; set; }
}

/// <summary>HAL links on a collection page.</summary>
public sealed class PageLinks
{
    /// <summary>Link to the next page.</summary>
    [JsonPropertyName("next")]
    public Href? Next { get; set; }
}

/// <summary>HAL link.</summary>
public sealed class Href
{
    /// <summary>Server relative URL.</summary>
    [JsonPropertyName("href")]
    public string? Value { get; set; }
}

/// <summary>Reference to an SVM.</summary>
public sealed class SvmRef
{
    /// <summary>SVM UUID.</summary>
    [JsonPropertyName("uuid")]
    public string? Uuid { get; set; }

    /// <summary>SVM name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

/// <summary>Reference to a named object.</summary>
public sealed class NamedRef
{
    /// <summary>Name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>Numeric identifier, where the object has one (export policies).</summary>
    [JsonPropertyName("id")]
    public long? Id { get; set; }
}

/// <summary>/api/storage/volumes record (subset).</summary>
public sealed class VolumeRecord
{
    /// <summary>Volume UUID.</summary>
    [JsonPropertyName("uuid")]
    public string? Uuid { get; set; }

    /// <summary>Volume name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>online, offline, restricted, mixed.</summary>
    [JsonPropertyName("state")]
    public string? State { get; set; }

    /// <summary>Owning SVM.</summary>
    [JsonPropertyName("svm")]
    public SvmRef? Svm { get; set; }

    /// <summary>NAS attributes.</summary>
    [JsonPropertyName("nas")]
    public VolumeNas? Nas { get; set; }
}

/// <summary>Volume NAS attributes.</summary>
public sealed class VolumeNas
{
    /// <summary>Junction path, for example /vol1.</summary>
    [JsonPropertyName("path")]
    public string? Path { get; set; }

    /// <summary>unix, ntfs, mixed.</summary>
    [JsonPropertyName("security_style")]
    public string? SecurityStyle { get; set; }

    /// <summary>Root directory owner UID.</summary>
    [JsonPropertyName("uid")]
    public long? Uid { get; set; }

    /// <summary>Root directory group GID.</summary>
    [JsonPropertyName("gid")]
    public long? Gid { get; set; }

    /// <summary>Root directory mode as a decimal number, for example 493 for 0755.</summary>
    [JsonPropertyName("unix_permissions")]
    public int? UnixPermissions { get; set; }

    /// <summary>Export policy applied to the volume.</summary>
    [JsonPropertyName("export_policy")]
    public NamedRef? ExportPolicy { get; set; }
}

/// <summary>/api/protocols/nfs/export-policies record.</summary>
public sealed class ExportPolicyRecord
{
    /// <summary>Policy ID used in rule URLs.</summary>
    [JsonPropertyName("id")]
    public long? Id { get; set; }

    /// <summary>Policy name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>Owning SVM.</summary>
    [JsonPropertyName("svm")]
    public SvmRef? Svm { get; set; }

    /// <summary>Rules when requested with fields=rules.</summary>
    [JsonPropertyName("rules")]
    public List<ExportRuleRecord>? Rules { get; set; }
}

/// <summary>Export rule client entry.</summary>
public sealed class ExportClientRecord
{
    /// <summary>clientmatch value.</summary>
    [JsonPropertyName("match")]
    public string? Match { get; set; }
}

/// <summary>/api/protocols/nfs/export-policies/{id}/rules record.</summary>
public sealed class ExportRuleRecord
{
    /// <summary>Rule index.</summary>
    [JsonPropertyName("index")]
    public int? Index { get; set; }

    /// <summary>Client match entries.</summary>
    [JsonPropertyName("clients")]
    public List<ExportClientRecord>? Clients { get; set; }

    /// <summary>any, nfs, nfs3, nfs4, cifs.</summary>
    [JsonPropertyName("protocols")]
    public List<string>? Protocols { get; set; }

    /// <summary>Read only rule flavours.</summary>
    [JsonPropertyName("ro_rule")]
    public List<string>? RoRule { get; set; }

    /// <summary>Read write rule flavours.</summary>
    [JsonPropertyName("rw_rule")]
    public List<string>? RwRule { get; set; }

    /// <summary>Superuser flavours.</summary>
    [JsonPropertyName("superuser")]
    public List<string>? Superuser { get; set; }

    /// <summary>Anonymous user, a UID or user name as a string.</summary>
    [JsonPropertyName("anonymous_user")]
    public string? AnonymousUser { get; set; }
}

/// <summary>/api/name-services/unix-users record.</summary>
public sealed class UnixUserRecord
{
    /// <summary>Owning SVM.</summary>
    [JsonPropertyName("svm")]
    public SvmRef? Svm { get; set; }

    /// <summary>User name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>UID.</summary>
    [JsonPropertyName("id")]
    public long? Id { get; set; }

    /// <summary>Primary GID.</summary>
    [JsonPropertyName("primary_gid")]
    public long? PrimaryGid { get; set; }

    /// <summary>Full name.</summary>
    [JsonPropertyName("full_name")]
    public string? FullName { get; set; }
}

/// <summary>Group member reference.</summary>
public sealed class UnixGroupMember
{
    /// <summary>Member user name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

/// <summary>/api/name-services/unix-groups record.</summary>
public sealed class UnixGroupRecord
{
    /// <summary>Owning SVM.</summary>
    [JsonPropertyName("svm")]
    public SvmRef? Svm { get; set; }

    /// <summary>Group name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>GID.</summary>
    [JsonPropertyName("id")]
    public long? Id { get; set; }

    /// <summary>Members, when requested with fields=users.</summary>
    [JsonPropertyName("users")]
    public List<UnixGroupMember>? Users { get; set; }
}

/// <summary>/api/protocols/nfs/services record (subset).</summary>
public sealed class NfsServiceRecord
{
    /// <summary>Owning SVM.</summary>
    [JsonPropertyName("svm")]
    public SvmRef? Svm { get; set; }

    /// <summary>Administratively enabled.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>online or offline.</summary>
    [JsonPropertyName("state")]
    public string? State { get; set; }

    /// <summary>Protocol versions.</summary>
    [JsonPropertyName("protocol")]
    public NfsServiceProtocol? Protocol { get; set; }
}

/// <summary>Protocol flags on the NFS service.</summary>
public sealed class NfsServiceProtocol
{
    /// <summary>NFSv3 enabled.</summary>
    [JsonPropertyName("v3_enabled")]
    public bool? V3Enabled { get; set; }

    /// <summary>NFSv4.0 enabled.</summary>
    [JsonPropertyName("v40_enabled")]
    public bool? V40Enabled { get; set; }
}

/// <summary>/api/cluster/jobs/{uuid} record.</summary>
public sealed class JobRecord
{
    /// <summary>Job UUID.</summary>
    [JsonPropertyName("uuid")]
    public string? Uuid { get; set; }

    /// <summary>queued, running, paused, success, failure.</summary>
    [JsonPropertyName("state")]
    public string? State { get; set; }

    /// <summary>Status message.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }

    /// <summary>Error code on failure.</summary>
    [JsonPropertyName("code")]
    public long? Code { get; set; }

    /// <summary>Description of the operation.</summary>
    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

/// <summary>Body of a 202 Accepted response.</summary>
public sealed class JobLinkResponse
{
    /// <summary>The job.</summary>
    [JsonPropertyName("job")]
    public JobRecord? Job { get; set; }
}

/// <summary>ONTAP error body: <c>{"error": {"message": "...", "code": "..."}}</c>.</summary>
public sealed class ErrorResponse
{
    /// <summary>The error.</summary>
    [JsonPropertyName("error")]
    public ErrorDetail? Error { get; set; }
}

/// <summary>Error detail.</summary>
public sealed class ErrorDetail
{
    /// <summary>Message.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }

    /// <summary>ONTAP error code, a numeric string.</summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    /// <summary>Field the error refers to.</summary>
    [JsonPropertyName("target")]
    public string? Target { get; set; }
}
