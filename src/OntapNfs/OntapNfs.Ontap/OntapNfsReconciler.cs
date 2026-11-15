using System.Globalization;
using OntapNfs.Core.Posix;
using OntapNfs.Ontap.Models;

namespace OntapNfs.Ontap;

/// <summary>What an ensure operation did.</summary>
public enum EnsureAction
{
    /// <summary>Actual already matched desired; nothing was sent.</summary>
    Unchanged,

    /// <summary>The object was created.</summary>
    Created,

    /// <summary>The object existed and was changed.</summary>
    Updated,
}

/// <summary>Outcome of an ensure operation.</summary>
/// <param name="Action">What happened.</param>
/// <param name="Subject">The object, for example <c>svm1/export-policy/app_nfs/rule</c>.</param>
/// <param name="Changes">Field level differences that were applied (empty when unchanged).</param>
public sealed record EnsureResult(EnsureAction Action, string Subject, IReadOnlyList<string> Changes);

/// <summary>Desired state cannot be reached without overriding another object.</summary>
public sealed class EnsureConflictException : InvalidOperationException
{
    /// <summary>Creates the exception.</summary>
    public EnsureConflictException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public EnsureConflictException()
        : base("Desired state conflicts with existing configuration.")
    {
    }

    /// <summary>Creates the exception.</summary>
    public EnsureConflictException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Idempotent ensure operations. Each reads actual state, diffs it with desired
/// state and sends only the create or patch needed, so running the same desired
/// state twice sends no writes the second time.
/// </summary>
public sealed class OntapNfsReconciler
{
    private readonly OntapClient _client;

    /// <summary>Creates a reconciler over a client.</summary>
    public OntapNfsReconciler(OntapClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    /// <summary>Ensures an export policy exists and returns it with the result.</summary>
    public async Task<(ExportPolicyRecord Policy, EnsureResult Result)> EnsureExportPolicyAsync(string svmName, string policyName, CancellationToken cancellationToken = default)
    {
        var subject = $"{svmName}/export-policy/{policyName}";
        var existing = await _client.GetExportPolicyAsync(svmName, policyName, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            return (existing, new EnsureResult(EnsureAction.Unchanged, subject, Array.Empty<string>()));
        }

        var created = await _client.CreateExportPolicyAsync(svmName, policyName, cancellationToken).ConfigureAwait(false);
        if (created.Id is null)
        {
            created = await _client.GetExportPolicyAsync(svmName, policyName, cancellationToken).ConfigureAwait(false) ?? created;
        }

        return (created, new EnsureResult(EnsureAction.Created, subject, new[] { "policy created" }));
    }

    /// <summary>
    /// Ensures a rule with the desired client match exists in the policy and has the
    /// desired ro, rw, superuser, anon and protocol settings. A rule is identified by its
    /// client match set, not its index, because indexes shift when rules are inserted.
    /// </summary>
    public async Task<EnsureResult> EnsureExportRuleAsync(string svmName, string policyName, ExportRule desired, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(desired);
        var (policy, _) = await EnsureExportPolicyAsync(svmName, policyName, cancellationToken).ConfigureAwait(false);
        var policyId = policy.Id ?? throw new OntapApiException($"export policy {policyName} has no id");
        var subject = $"{svmName}/export-policy/{policyName}/rule[{string.Join(",", desired.ClientMatch)}]";

        var rules = await _client.GetExportRulesAsync(policyId, cancellationToken).ConfigureAwait(false);
        var desiredClients = desired.ClientMatch.Select(ExportRule.Normalize).ToHashSet(StringComparer.Ordinal);
        var match = rules.FirstOrDefault(r => (r.Clients ?? new()).Select(c => ExportRule.Normalize(c.Match ?? string.Empty)).ToHashSet(StringComparer.Ordinal).SetEquals(desiredClients));

        if (match is null)
        {
            var indexFree = rules.All(r => r.Index != desired.Index) && desired.Index > 0;
            await _client.CreateExportRuleAsync(policyId, ExportRuleMapper.ToRecord(desired, includeIndex: indexFree), cancellationToken).ConfigureAwait(false);
            return new EnsureResult(EnsureAction.Created, subject, new[] { "rule created" + (indexFree ? " at index " + desired.Index.ToString(CultureInfo.InvariantCulture) : string.Empty) });
        }

        var actual = ExportRuleMapper.ToCore(match);
        var changes = DiffRule(actual, desired);
        if (changes.Count == 0)
        {
            return new EnsureResult(EnsureAction.Unchanged, subject, changes);
        }

        var patch = ExportRuleMapper.ToRecord(desired);
        patch.Clients = null;
        await _client.PatchExportRuleAsync(policyId, match.Index ?? actual.Index, patch, cancellationToken).ConfigureAwait(false);
        return new EnsureResult(EnsureAction.Updated, subject, changes);
    }

    /// <summary>Ensures a UNIX group exists with the given GID. Refuses to steal a GID used by another group.</summary>
    public async Task<EnsureResult> EnsureUnixGroupAsync(string svmName, string name, long gid, CancellationToken cancellationToken = default)
    {
        var subject = $"{svmName}/unix-group/{name}";
        var byGid = await _client.GetUnixGroupsAsync(svmName, gid: gid, cancellationToken: cancellationToken).ConfigureAwait(false);
        var holder = byGid.FirstOrDefault(g => g.Name != name);
        if (holder is not null)
        {
            throw new EnsureConflictException($"GID {gid} already belongs to group '{holder.Name}' on {svmName}");
        }

        var existing = (await _client.GetUnixGroupsAsync(svmName, name, cancellationToken: cancellationToken).ConfigureAwait(false)).FirstOrDefault();
        if (existing is null)
        {
            await _client.CreateUnixGroupAsync(new UnixGroupRecord { Svm = new SvmRef { Name = svmName }, Name = name, Id = gid }, cancellationToken).ConfigureAwait(false);
            return new EnsureResult(EnsureAction.Created, subject, new[] { "gid " + gid.ToString(CultureInfo.InvariantCulture) });
        }

        if (existing.Id == gid)
        {
            return new EnsureResult(EnsureAction.Unchanged, subject, Array.Empty<string>());
        }

        await _client.PatchUnixGroupAsync(SvmUuid(existing.Svm, subject), name, new UnixGroupRecord { Id = gid }, cancellationToken).ConfigureAwait(false);
        return new EnsureResult(EnsureAction.Updated, subject, new[] { $"gid {existing.Id} -> {gid}" });
    }

    /// <summary>
    /// Ensures the supplementary members of a UNIX group. Missing members are added.
    /// With <paramref name="removeOthers"/>, members not in the desired set are removed,
    /// which is how an IdentityIQ revocation of a governed group lands on ONTAP.
    /// </summary>
    public async Task<EnsureResult> EnsureUnixGroupMembersAsync(string svmName, string groupName, IEnumerable<string> desiredMembers, bool removeOthers = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(desiredMembers);
        var subject = $"{svmName}/unix-group/{groupName}/users";
        var group = (await _client.GetUnixGroupsAsync(svmName, groupName, cancellationToken: cancellationToken).ConfigureAwait(false)).FirstOrDefault()
            ?? throw new EnsureConflictException($"UNIX group {groupName} does not exist on {svmName}");
        var actual = (group.Users ?? new()).Select(u => u.Name).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var desired = desiredMembers.ToHashSet(StringComparer.Ordinal);
        var toAdd = desired.Except(actual).Order(StringComparer.Ordinal).ToList();
        var toRemove = removeOthers ? actual.Except(desired).Order(StringComparer.Ordinal).ToList() : new List<string>();
        if (toAdd.Count == 0 && toRemove.Count == 0)
        {
            return new EnsureResult(EnsureAction.Unchanged, subject, Array.Empty<string>());
        }

        var svmUuid = SvmUuid(group.Svm, subject);

        // Revocation before grant, as in the change planner: never hold old and new access at once.
        foreach (var user in toRemove)
        {
            await _client.RemoveUnixGroupMemberAsync(svmUuid, groupName, user, cancellationToken).ConfigureAwait(false);
        }

        if (toAdd.Count > 0)
        {
            await _client.AddUnixGroupMembersAsync(svmUuid, groupName, toAdd, cancellationToken).ConfigureAwait(false);
        }

        var changes = toRemove.Select(u => "- " + u).Concat(toAdd.Select(u => "+ " + u)).ToList();
        return new EnsureResult(EnsureAction.Updated, subject, changes);
    }

    /// <summary>Ensures a UNIX user exists with the given UID, primary GID and full name. Refuses to reuse a UID held by another user.</summary>
    public async Task<EnsureResult> EnsureUnixUserAsync(string svmName, UnixUser desired, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(desired);
        var subject = $"{svmName}/unix-user/{desired.Name}";
        if (desired.Uid is UnixIds.Root or UnixIds.Nobody or UnixIds.AnonymousDenied)
        {
            throw new EnsureConflictException($"UID {desired.Uid} is reserved and cannot be assigned to '{desired.Name}'");
        }

        var byUid = await _client.GetUnixUsersAsync(svmName, uid: desired.Uid, cancellationToken: cancellationToken).ConfigureAwait(false);
        var holder = byUid.FirstOrDefault(u => u.Name != desired.Name);
        if (holder is not null)
        {
            throw new EnsureConflictException($"UID {desired.Uid} already belongs to '{holder.Name}' on {svmName}");
        }

        var existing = (await _client.GetUnixUsersAsync(svmName, desired.Name, cancellationToken: cancellationToken).ConfigureAwait(false)).FirstOrDefault();
        if (existing is null)
        {
            await _client.CreateUnixUserAsync(new UnixUserRecord
            {
                Svm = new SvmRef { Name = svmName },
                Name = desired.Name,
                Id = desired.Uid,
                PrimaryGid = desired.PrimaryGid,
                FullName = desired.FullName,
            }, cancellationToken).ConfigureAwait(false);
            return new EnsureResult(EnsureAction.Created, subject, new[] { $"uid {desired.Uid}, primary gid {desired.PrimaryGid}" });
        }

        var changes = new List<string>();
        var patch = new UnixUserRecord();
        if (existing.Id != desired.Uid)
        {
            changes.Add($"uid {existing.Id} -> {desired.Uid}");
            patch.Id = desired.Uid;
        }

        if (existing.PrimaryGid != desired.PrimaryGid)
        {
            changes.Add($"primary_gid {existing.PrimaryGid} -> {desired.PrimaryGid}");
            patch.PrimaryGid = desired.PrimaryGid;
        }

        if (desired.FullName is not null && existing.FullName != desired.FullName)
        {
            changes.Add("full_name");
            patch.FullName = desired.FullName;
        }

        if (changes.Count == 0)
        {
            return new EnsureResult(EnsureAction.Unchanged, subject, changes);
        }

        await _client.PatchUnixUserAsync(SvmUuid(existing.Svm, subject), desired.Name, patch, cancellationToken).ConfigureAwait(false);
        return new EnsureResult(EnsureAction.Updated, subject, changes);
    }

    /// <summary>Ensures a volume uses the named export policy. Waits for the volume PATCH job.</summary>
    public async Task<EnsureResult> EnsureVolumeExportPolicyAsync(string svmName, string volumeName, string policyName, CancellationToken cancellationToken = default)
    {
        var subject = $"{svmName}/volume/{volumeName}";
        var volume = await _client.GetVolumeAsync(svmName, volumeName, cancellationToken).ConfigureAwait(false)
            ?? throw new EnsureConflictException($"volume {volumeName} does not exist on {svmName}");
        var current = volume.Nas?.ExportPolicy?.Name;
        if (current == policyName)
        {
            return new EnsureResult(EnsureAction.Unchanged, subject, Array.Empty<string>());
        }

        await _client.SetVolumeExportPolicyAsync(volume.Uuid ?? throw new OntapApiException($"volume {volumeName} has no uuid"), policyName, cancellationToken).ConfigureAwait(false);
        return new EnsureResult(EnsureAction.Updated, subject, new[] { $"export policy {current ?? "(none)"} -> {policyName}" });
    }

    /// <summary>Reads an export policy with its rules as a core model for evaluation.</summary>
    public async Task<ExportPolicy?> ReadExportPolicyAsync(string svmName, string policyName, CancellationToken cancellationToken = default)
    {
        var policy = await _client.GetExportPolicyAsync(svmName, policyName, cancellationToken).ConfigureAwait(false);
        if (policy?.Id is not long id)
        {
            return null;
        }

        var users = await ReadUnixUsersAsync(svmName, cancellationToken).ConfigureAwait(false);
        var rules = await _client.GetExportRulesAsync(id, cancellationToken).ConfigureAwait(false);
        return ExportRuleMapper.ToCore(policyName, rules, n => users.FirstOrDefault(u => u.Name == n)?.Uid);
    }

    /// <summary>Reads all UNIX users on the SVM as core records.</summary>
    public async Task<IReadOnlyList<UnixUser>> ReadUnixUsersAsync(string svmName, CancellationToken cancellationToken = default)
        => (await _client.GetUnixUsersAsync(svmName, cancellationToken: cancellationToken).ConfigureAwait(false))
            .Where(u => u.Name is not null && u.Id is not null)
            .Select(u => new UnixUser(u.Name!, u.Id!.Value, u.PrimaryGid ?? UnixIds.Nobody, u.FullName))
            .ToList();

    /// <summary>Reads all UNIX groups on the SVM as core records.</summary>
    public async Task<IReadOnlyList<UnixGroup>> ReadUnixGroupsAsync(string svmName, CancellationToken cancellationToken = default)
        => (await _client.GetUnixGroupsAsync(svmName, cancellationToken: cancellationToken).ConfigureAwait(false))
            .Where(g => g.Name is not null && g.Id is not null)
            .Select(g => new UnixGroup(g.Name!, g.Id!.Value, (g.Users ?? new()).Select(m => m.Name).OfType<string>().ToList()))
            .ToList();

    /// <summary>
    /// Validates a service account against live SVM state: NFS service with v3 enabled,
    /// UNIX user and groups, and the export policy on the volume.
    /// </summary>
    public async Task<ValidationReport> ValidateServiceAccountAsync(string svmName, string volumeName, ServiceAccountSpec spec, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(spec);
        var issues = new List<ValidationIssue>();
        var services = await _client.GetNfsServicesAsync(svmName, cancellationToken).ConfigureAwait(false);
        var nfs = services.FirstOrDefault();
        if (nfs is null || nfs.Enabled == false || nfs.Protocol?.V3Enabled == false)
        {
            issues.Add(new ValidationIssue(ValidationSeverity.Error, "NFSV3_DISABLED", $"NFS service on {svmName} is missing, disabled, or has NFSv3 off"));
        }

        var volume = await _client.GetVolumeAsync(svmName, volumeName, cancellationToken).ConfigureAwait(false);
        var policyName = volume?.Nas?.ExportPolicy?.Name;
        if (policyName is null)
        {
            issues.Add(new ValidationIssue(ValidationSeverity.Error, "VOLUME_NOT_EXPORTED", $"volume {volumeName} not found or has no export policy"));
            return new ValidationReport(issues, null);
        }

        var policy = await ReadExportPolicyAsync(svmName, policyName, cancellationToken).ConfigureAwait(false)
            ?? new ExportPolicy(policyName, Array.Empty<ExportRule>());
        var users = await ReadUnixUsersAsync(svmName, cancellationToken).ConfigureAwait(false);
        var groups = await ReadUnixGroupsAsync(svmName, cancellationToken).ConfigureAwait(false);

        var target = spec.TargetDirectory;
        if (target is null && volume?.Nas is { Uid: long vu, Gid: long vg, UnixPermissions: int perms })
        {
            target = new PosixOwnership(vu, vg, (UnixFileMode)perms);
        }

        var report = ServiceAccountValidator.Validate(spec with { TargetDirectory = target }, users, groups, policy);
        issues.AddRange(report.Issues);
        return new ValidationReport(issues, report.Decision);
    }

    internal static List<string> DiffRule(ExportRule actual, ExportRule desired)
    {
        var changes = new List<string>();
        Compare("ro_rule", actual.RoRule, desired.RoRule, changes);
        Compare("rw_rule", actual.RwRule, desired.RwRule, changes);
        Compare("superuser", actual.Superuser, desired.Superuser, changes);
        Compare("protocols", actual.Protocols, desired.Protocols, changes);
        if (actual.AnonUid != desired.AnonUid)
        {
            changes.Add($"anonymous_user {actual.AnonUid} -> {desired.AnonUid}");
        }

        return changes;
    }

    private static void Compare<T>(string field, IReadOnlySet<T> actual, IReadOnlySet<T> desired, List<string> changes)
        where T : struct, Enum
    {
        if (!actual.SetEquals(desired))
        {
            changes.Add($"{field} [{string.Join(",", ExportRuleMapper.Names(actual))}] -> [{string.Join(",", ExportRuleMapper.Names(desired))}]");
        }
    }

    private static string SvmUuid(SvmRef? svm, string subject)
        => svm?.Uuid ?? throw new OntapApiException($"{subject} was returned without svm.uuid, which the PATCH URL needs");
}
