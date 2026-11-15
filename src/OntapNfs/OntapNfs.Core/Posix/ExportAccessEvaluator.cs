namespace OntapNfs.Core.Posix;

/// <summary>Access an export grants to a request.</summary>
public enum ExportAccess
{
    /// <summary>No access.</summary>
    None,

    /// <summary>Read only.</summary>
    ReadOnly,

    /// <summary>Read and write.</summary>
    ReadWrite,
}

/// <summary>Result of evaluating an export policy for one client and credential.</summary>
/// <param name="Access">Granted access.</param>
/// <param name="RuleIndex">Index of the rule that matched, if any.</param>
/// <param name="EffectiveUid">UID the server will use for permission checks and new file ownership.</param>
/// <param name="EffectiveGid">Primary GID the server will use.</param>
/// <param name="MappedToAnonymous">True when the credential was replaced by the anonymous user.</param>
/// <param name="RootSquashed">True when UID 0 was squashed because superuser did not allow the flavour.</param>
/// <param name="Reason">Human readable explanation.</param>
public sealed record ExportAccessDecision(
    ExportAccess Access,
    int? RuleIndex,
    long EffectiveUid,
    long EffectiveGid,
    bool MappedToAnonymous,
    bool RootSquashed,
    string Reason);

/// <summary>
/// Evaluates ONTAP export policy semantics for NFSv3 requests.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Rules are tried in ascending index order; the first rule whose protocol and client match fit is used. No match means no access.</item>
/// <item>For rorule and rwrule: a listed flavour or <c>any</c> grants access as the asserted identity; <c>none</c> grants access as the anonymous user; anything else denies.</item>
/// <item>Write needs read: a client with no read access has no access at all.</item>
/// <item>UID 0 is kept only when superuser lists the flavour or <c>any</c>; otherwise it is squashed to the anonymous UID (root squash).</item>
/// <item>An anonymous UID of 65535 denies every request that maps to anonymous. An anonymous UID of 0 hands anonymous requests root, which the evaluator reports.</item>
/// <item>The anonymous GID is taken to equal the anonymous UID, the nobody and nogroup convention (65534). ONTAP resolves it from the anonymous user's primary group, so a non default anonymous user can differ.</item>
/// </list>
/// </remarks>
public static class ExportAccessEvaluator
{
    /// <summary>Evaluates the policy for a client asserting a UID and GID.</summary>
    public static ExportAccessDecision Evaluate(
        ExportPolicy policy,
        NfsClient client,
        long uid,
        long gid,
        SecurityFlavor flavor = SecurityFlavor.Sys,
        NfsProtocol protocol = NfsProtocol.Nfs3)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(client);

        var rule = policy.Rules
            .OrderBy(r => r.Index)
            .FirstOrDefault(r => r.AppliesTo(protocol) && ClientMatcher.Matches(r.ClientMatch, client));
        if (rule is null)
        {
            return new ExportAccessDecision(ExportAccess.None, null, uid, gid, false, false,
                $"no rule in export policy '{policy.Name}' matches client {client.Address}");
        }

        var read = Grant(rule.RoRule, flavor);
        if (read == GrantKind.Denied)
        {
            return new ExportAccessDecision(ExportAccess.None, rule.Index, uid, gid, false, false,
                $"rule {rule.Index} rorule does not allow {Name(flavor)}");
        }

        var write = Grant(rule.RwRule, flavor);
        var anonymous = read == GrantKind.Anonymous;
        var squashed = false;
        if (!anonymous && uid == UnixIds.Root && !(rule.Superuser.Contains(flavor) || rule.Superuser.Contains(SecurityFlavor.Any)))
        {
            anonymous = true;
            squashed = true;
        }

        if (anonymous && rule.AnonUid == UnixIds.AnonymousDenied)
        {
            return new ExportAccessDecision(ExportAccess.None, rule.Index, rule.AnonUid, rule.AnonUid, true, squashed,
                $"rule {rule.Index} maps the request to anonymous and anon=65535 denies anonymous access");
        }

        var effUid = anonymous ? rule.AnonUid : uid;
        var effGid = anonymous ? rule.AnonUid : gid;
        var access = write == GrantKind.Denied ? ExportAccess.ReadOnly : ExportAccess.ReadWrite;

        var reason = $"rule {rule.Index} grants {(access == ExportAccess.ReadWrite ? "read write" : "read only")}";
        if (squashed)
        {
            reason += $"; root squashed to anon {rule.AnonUid}";
        }
        else if (anonymous)
        {
            reason += $"; mapped to anon {rule.AnonUid} by rorule none";
        }

        if (write == GrantKind.Anonymous && !anonymous)
        {
            reason += "; writes are performed as the anonymous user (rwrule none)";
        }

        if (anonymous && rule.AnonUid == UnixIds.Root)
        {
            reason += "; anon=0 gives anonymous requests root";
        }

        return new ExportAccessDecision(access, rule.Index, effUid, effGid, anonymous, squashed, reason);
    }

    private enum GrantKind
    {
        Denied,
        Real,
        Anonymous,
    }

    private static GrantKind Grant(IReadOnlySet<SecurityFlavor> rule, SecurityFlavor flavor)
    {
        if (rule.Contains(SecurityFlavor.Never) && !rule.Contains(flavor))
        {
            return GrantKind.Denied;
        }

        if (rule.Contains(flavor) || rule.Contains(SecurityFlavor.Any))
        {
            return GrantKind.Real;
        }

        return rule.Contains(SecurityFlavor.None) ? GrantKind.Anonymous : GrantKind.Denied;
    }

    private static string Name(SecurityFlavor f) => f.ToString().ToLowerInvariant();
}
