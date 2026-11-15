namespace OntapNfs.Core.Posix;

/// <summary>Severity of a validation finding.</summary>
public enum ValidationSeverity
{
    /// <summary>Works, but worth a reviewer's attention.</summary>
    Warning,

    /// <summary>The service account will not work as intended.</summary>
    Error,
}

/// <summary>One finding.</summary>
/// <param name="Severity">Severity.</param>
/// <param name="Code">Stable machine readable code.</param>
/// <param name="Message">Explanation.</param>
public sealed record ValidationIssue(ValidationSeverity Severity, string Code, string Message);

/// <summary>Outcome of validating a service account against an export.</summary>
/// <param name="Issues">All findings.</param>
/// <param name="Decision">The export decision, when the user could be resolved.</param>
public sealed record ValidationReport(IReadOnlyList<ValidationIssue> Issues, ExportAccessDecision? Decision)
{
    /// <summary>True when there are no errors.</summary>
    public bool IsValid => Issues.All(i => i.Severity != ValidationSeverity.Error);

    /// <summary>True when a finding with the code exists.</summary>
    public bool Has(string code) => Issues.Any(i => i.Code == code);
}

/// <summary>What the service account must be able to do.</summary>
/// <param name="AccountName">Login name of the service account, for example <c>svc_tomcat</c>.</param>
/// <param name="Client">The host the account connects from.</param>
/// <param name="RequiresWrite">True when it creates or replaces files (WAR deployment does).</param>
/// <param name="TargetDirectory">Optional ownership of the directory it writes into.</param>
public sealed record ServiceAccountSpec(string AccountName, NfsClient Client, bool RequiresWrite, PosixOwnership? TargetDirectory = null);

/// <summary>
/// Checks that a service account maps to a valid UID and GID on the SVM (ONTAP
/// unix-user and unix-group, or the LDAP or NIS view of them) and that the export
/// policy lets that identity in with the access it needs.
/// </summary>
public static class ServiceAccountValidator
{
    /// <summary>Validation codes.</summary>
    public static class Codes
    {
        /// <summary>The account name is not a UNIX user on the SVM.</summary>
        public const string UserNotFound = "USER_NOT_FOUND";

        /// <summary>The UID is reserved (65534 nobody, 65535 deny).</summary>
        public const string ReservedUid = "RESERVED_UID";

        /// <summary>Two users share the UID, so file ownership is ambiguous.</summary>
        public const string DuplicateUid = "DUPLICATE_UID";

        /// <summary>The primary GID is not a known group.</summary>
        public const string PrimaryGroupMissing = "PRIMARY_GROUP_MISSING";

        /// <summary>A group shares the primary GID with another name.</summary>
        public const string DuplicateGid = "DUPLICATE_GID";

        /// <summary>No export access.</summary>
        public const string ExportDenied = "EXPORT_DENIED";

        /// <summary>Write needed but export is read only.</summary>
        public const string WriteNotAllowed = "WRITE_NOT_ALLOWED";

        /// <summary>Root is squashed to anonymous.</summary>
        public const string RootSquashed = "ROOT_SQUASHED";

        /// <summary>Running as root over NFS is discouraged.</summary>
        public const string RunsAsRoot = "RUNS_AS_ROOT";

        /// <summary>Identity mapped to anonymous; created files will be owned by anon.</summary>
        public const string MappedToAnonymous = "MAPPED_TO_ANONYMOUS";

        /// <summary>Anonymous is mapped to UID 0.</summary>
        public const string AnonIsRoot = "ANON_IS_ROOT";

        /// <summary>More than 16 groups: AUTH_SYS truncates the list.</summary>
        public const string TooManyGroups = "AUTH_SYS_GROUP_LIMIT";

        /// <summary>Mode bits on the target directory deny the effective identity.</summary>
        public const string DirectoryNotWritable = "DIRECTORY_NOT_WRITABLE";

        /// <summary>Mode bits on the target directory deny read.</summary>
        public const string DirectoryNotReadable = "DIRECTORY_NOT_READABLE";
    }

    /// <summary>Validates the account.</summary>
    public static ValidationReport Validate(
        ServiceAccountSpec spec,
        IReadOnlyCollection<UnixUser> users,
        IReadOnlyCollection<UnixGroup> groups,
        ExportPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(groups);
        ArgumentNullException.ThrowIfNull(policy);

        var issues = new List<ValidationIssue>();
        var user = users.FirstOrDefault(u => u.Name == spec.AccountName);
        if (user is null)
        {
            issues.Add(Error(Codes.UserNotFound, $"'{spec.AccountName}' is not a UNIX user on the SVM; requests will be treated as an unknown UID"));
            return new ValidationReport(issues, null);
        }

        if (user.Uid is UnixIds.Nobody or UnixIds.AnonymousDenied || user.Uid < 0 || user.Uid > uint.MaxValue)
        {
            issues.Add(Error(Codes.ReservedUid, $"UID {user.Uid} of '{user.Name}' is reserved or out of range"));
        }

        var sharing = users.Where(u => u.Uid == user.Uid && u.Name != user.Name).Select(u => u.Name).ToList();
        if (sharing.Count > 0)
        {
            issues.Add(Error(Codes.DuplicateUid, $"UID {user.Uid} is also used by {string.Join(", ", sharing)}; ownership on the export is ambiguous"));
        }

        var primary = groups.FirstOrDefault(g => g.Gid == user.PrimaryGid);
        if (primary is null)
        {
            issues.Add(Error(Codes.PrimaryGroupMissing, $"primary GID {user.PrimaryGid} of '{user.Name}' is not a UNIX group on the SVM"));
        }
        else
        {
            var otherNames = groups.Where(g => g.Gid == user.PrimaryGid && g.Name != primary.Name).Select(g => g.Name).ToList();
            if (otherNames.Count > 0)
            {
                issues.Add(Warning(Codes.DuplicateGid, $"GID {user.PrimaryGid} is named both {primary.Name} and {string.Join(", ", otherNames)}"));
            }
        }

        var supplementary = groups.Where(g => g.Members.Contains(user.Name) && g.Gid != user.PrimaryGid).Select(g => g.Gid).Distinct().ToList();
        if (supplementary.Count > UnixIds.AuthSysMaxGroups)
        {
            issues.Add(Warning(Codes.TooManyGroups,
                $"'{user.Name}' is in {supplementary.Count} supplementary groups; AUTH_SYS sends at most {UnixIds.AuthSysMaxGroups}. Enable ONTAP auth-sys-extended-groups or reduce membership"));
        }

        if (user.Uid == UnixIds.Root)
        {
            issues.Add(Warning(Codes.RunsAsRoot, "the service account is root; run the app server as a dedicated unprivileged account"));
        }

        var decision = ExportAccessEvaluator.Evaluate(policy, spec.Client, user.Uid, user.PrimaryGid);
        switch (decision.Access)
        {
            case ExportAccess.None:
                issues.Add(Error(Codes.ExportDenied, decision.Reason));
                return new ValidationReport(issues, decision);
            case ExportAccess.ReadOnly when spec.RequiresWrite:
                issues.Add(Error(Codes.WriteNotAllowed, decision.Reason + "; the account needs write"));
                break;
        }

        if (decision.RootSquashed)
        {
            issues.Add(Warning(Codes.RootSquashed, decision.Reason));
        }
        else if (decision.MappedToAnonymous)
        {
            issues.Add((spec.RequiresWrite ? (Func<string, string, ValidationIssue>)Error : Warning)(
                Codes.MappedToAnonymous,
                $"requests map to anon {decision.EffectiveUid}; files the account creates will not be owned by it"));
        }

        if (decision.MappedToAnonymous && decision.EffectiveUid == UnixIds.Root)
        {
            issues.Add(Error(Codes.AnonIsRoot, "anon=0 grants root to every anonymous request"));
        }

        if (spec.TargetDirectory is { } dir)
        {
            var gids = decision.MappedToAnonymous
                ? new List<long> { decision.EffectiveGid }
                : supplementary.Take(UnixIds.AuthSysMaxGroups).Append(user.PrimaryGid).ToList();
            if (!PosixPermissions.Allows(dir, decision.EffectiveUid, gids, PosixPermissions.Want.Read | PosixPermissions.Want.Execute))
            {
                issues.Add(Error(Codes.DirectoryNotReadable, DescribeDir("read and search", dir, decision.EffectiveUid)));
            }

            if (spec.RequiresWrite && !PosixPermissions.CanModifyDirectory(dir, decision.EffectiveUid, gids))
            {
                issues.Add(Error(Codes.DirectoryNotWritable, DescribeDir("write", dir, decision.EffectiveUid)));
            }
        }

        return new ValidationReport(issues, decision);
    }

    private static string DescribeDir(string what, PosixOwnership dir, long uid)
        => $"UID {uid} cannot {what} the target directory (owner {dir.Uid}, group {dir.Gid}, mode {Convert.ToString((int)dir.Mode, 8)})";

    private static ValidationIssue Error(string code, string message) => new(ValidationSeverity.Error, code, message);

    private static ValidationIssue Warning(string code, string message) => new(ValidationSeverity.Warning, code, message);
}
