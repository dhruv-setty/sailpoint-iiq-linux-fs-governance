namespace OntapNfs.Core.Posix;

/// <summary>Well known UNIX identifiers.</summary>
public static class UnixIds
{
    /// <summary>Superuser.</summary>
    public const long Root = 0;

    /// <summary>nobody / nogroup on Linux and the ONTAP default anonymous user.</summary>
    public const long Nobody = 65534;

    /// <summary>ONTAP: an anonymous user of 65535 denies access to requests that map to anonymous.</summary>
    public const long AnonymousDenied = 65535;

    /// <summary>NFSv3 AUTH_SYS carries at most this many supplementary GIDs (RFC 5531 appendix A).</summary>
    public const int AuthSysMaxGroups = 16;
}

/// <summary>A UNIX user as held by ONTAP <c>vserver services name-service unix-user</c> or /etc/passwd.</summary>
/// <param name="Name">Login name.</param>
/// <param name="Uid">Numeric user ID.</param>
/// <param name="PrimaryGid">Primary group ID.</param>
/// <param name="FullName">GECOS or ONTAP full name.</param>
public sealed record UnixUser(string Name, long Uid, long PrimaryGid, string? FullName = null);

/// <summary>A UNIX group as held by ONTAP <c>unix-group</c> or /etc/group.</summary>
/// <param name="Name">Group name.</param>
/// <param name="Gid">Numeric group ID.</param>
/// <param name="Members">Supplementary member login names.</param>
public sealed record UnixGroup(string Name, long Gid, IReadOnlyList<string> Members)
{
    /// <summary>Creates a group with no supplementary members.</summary>
    public UnixGroup(string name, long gid)
        : this(name, gid, Array.Empty<string>())
    {
    }
}

/// <summary>ONTAP export rule security types (<c>-rorule</c>, <c>-rwrule</c>, <c>-superuser</c>).</summary>
public enum SecurityFlavor
{
    /// <summary>Any security type is accepted.</summary>
    Any,

    /// <summary>Not listed flavours are accepted as the anonymous user.</summary>
    None,

    /// <summary>Never allow.</summary>
    Never,

    /// <summary>AUTH_SYS (AUTH_UNIX): the client asserts UID and GIDs. NFSv3 default.</summary>
    Sys,

    /// <summary>Kerberos v5 authentication.</summary>
    Krb5,

    /// <summary>Kerberos v5 with integrity.</summary>
    Krb5i,

    /// <summary>Kerberos v5 with privacy.</summary>
    Krb5p,

    /// <summary>NTLM.</summary>
    Ntlm,
}

/// <summary>NFS protocol versions an export rule applies to.</summary>
public enum NfsProtocol
{
    /// <summary>All versions.</summary>
    Any,

    /// <summary>Any NFS version.</summary>
    Nfs,

    /// <summary>NFSv3.</summary>
    Nfs3,

    /// <summary>NFSv4 and later.</summary>
    Nfs4,
}

/// <summary>
/// One ONTAP export policy rule. Rules are evaluated in ascending
/// <see cref="Index"/> order and the first rule whose client match fits wins.
/// </summary>
/// <param name="Index">Rule index (ONTAP <c>-ruleindex</c>).</param>
/// <param name="ClientMatch">Client match entries: IP, CIDR, host name, <c>.domain</c> suffix, or <c>0.0.0.0/0</c>.</param>
/// <param name="RoRule">Flavours granted read access.</param>
/// <param name="RwRule">Flavours granted write access.</param>
/// <param name="Superuser">Flavours for which UID 0 is kept rather than squashed.</param>
/// <param name="AnonUid">UID that squashed and anonymous requests map to.</param>
/// <param name="Protocols">Protocols the rule applies to.</param>
public sealed record ExportRule(
    int Index,
    IReadOnlyList<string> ClientMatch,
    IReadOnlySet<SecurityFlavor> RoRule,
    IReadOnlySet<SecurityFlavor> RwRule,
    IReadOnlySet<SecurityFlavor> Superuser,
    long AnonUid,
    IReadOnlySet<NfsProtocol> Protocols)
{
    /// <summary>
    /// A rule for NFSv3 AUTH_SYS clients. <paramref name="readWrite"/> sets rwrule to sys;
    /// <paramref name="rootSquash"/> false keeps UID 0 (superuser sys), otherwise superuser none.
    /// </summary>
    public static ExportRule ForSys(int index, string clientMatch, bool readWrite, bool rootSquash = true, long anonUid = UnixIds.Nobody)
        => new(
            index,
            new[] { clientMatch },
            new HashSet<SecurityFlavor> { SecurityFlavor.Sys },
            new HashSet<SecurityFlavor> { readWrite ? SecurityFlavor.Sys : SecurityFlavor.Never },
            new HashSet<SecurityFlavor> { rootSquash ? SecurityFlavor.None : SecurityFlavor.Sys },
            anonUid,
            new HashSet<NfsProtocol> { NfsProtocol.Nfs3 });

    /// <summary>True when the rule applies to the given protocol. An empty set applies to none.</summary>
    public bool AppliesTo(NfsProtocol protocol)
        => Protocols.Contains(NfsProtocol.Any)
            || Protocols.Contains(protocol)
            || (Protocols.Contains(NfsProtocol.Nfs) && protocol is NfsProtocol.Nfs3 or NfsProtocol.Nfs4);

    /// <summary>Value equality on the rule's effect, ignoring index and collection identity.</summary>
    public bool SameEffectAs(ExportRule other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return ClientMatch.Select(Normalize).ToHashSet(StringComparer.Ordinal)
                .SetEquals(other.ClientMatch.Select(Normalize))
            && RoRule.SetEquals(other.RoRule)
            && RwRule.SetEquals(other.RwRule)
            && Superuser.SetEquals(other.Superuser)
            && AnonUid == other.AnonUid
            && Protocols.SetEquals(other.Protocols);
    }

    /// <summary>Canonical form of a client match entry for comparison.</summary>
    public static string Normalize(string match)
    {
        ArgumentNullException.ThrowIfNull(match);
        return match.Trim().ToLowerInvariant();
    }
}

/// <summary>An ONTAP export policy: a named, ordered list of rules on one SVM.</summary>
/// <param name="Name">Policy name.</param>
/// <param name="Rules">Rules; evaluation sorts by index.</param>
public sealed record ExportPolicy(string Name, IReadOnlyList<ExportRule> Rules);

/// <summary>An NFS client as the server sees it.</summary>
/// <param name="Address">Source IP address.</param>
/// <param name="HostName">Reverse resolved host name, if known.</param>
public sealed record NfsClient(System.Net.IPAddress Address, string? HostName = null);
