using System.Globalization;
using OntapNfs.Core.Posix;
using OntapNfs.Ontap.Models;

namespace OntapNfs.Ontap;

/// <summary>Converts between ONTAP REST export rule records and the core evaluation model.</summary>
public static class ExportRuleMapper
{
    private static readonly Dictionary<string, SecurityFlavor> Flavors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["any"] = SecurityFlavor.Any,
        ["none"] = SecurityFlavor.None,
        ["never"] = SecurityFlavor.Never,
        ["sys"] = SecurityFlavor.Sys,
        ["krb5"] = SecurityFlavor.Krb5,
        ["krb5i"] = SecurityFlavor.Krb5i,
        ["krb5p"] = SecurityFlavor.Krb5p,
        ["ntlm"] = SecurityFlavor.Ntlm,
    };

    private static readonly Dictionary<string, NfsProtocol> Protocols = new(StringComparer.OrdinalIgnoreCase)
    {
        ["any"] = NfsProtocol.Any,
        ["nfs"] = NfsProtocol.Nfs,
        ["nfs3"] = NfsProtocol.Nfs3,
        ["nfs4"] = NfsProtocol.Nfs4,
    };

    /// <summary>Converts a REST record to a core rule.</summary>
    /// <param name="record">The record.</param>
    /// <param name="resolveUserName">Resolves an anonymous user given by name to a UID.</param>
    /// <exception cref="FormatException">An unknown flavour, or an anonymous user name that cannot be resolved.</exception>
    public static ExportRule ToCore(ExportRuleRecord record, Func<string, long?>? resolveUserName = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        return new ExportRule(
            record.Index ?? 0,
            (record.Clients ?? new()).Select(c => c.Match ?? string.Empty).Where(m => m.Length > 0).ToList(),
            ParseFlavors(record.RoRule),
            ParseFlavors(record.RwRule),
            ParseFlavors(record.Superuser),
            ParseAnon(record.AnonymousUser, resolveUserName),
            ParseProtocols(record.Protocols));
    }

    /// <summary>Converts a core rule to a REST record. The index is included only when asked.</summary>
    public static ExportRuleRecord ToRecord(ExportRule rule, bool includeIndex = false)
    {
        ArgumentNullException.ThrowIfNull(rule);
        return new ExportRuleRecord
        {
            Index = includeIndex ? rule.Index : null,
            Clients = rule.ClientMatch.Select(m => new ExportClientRecord { Match = m }).ToList(),
            Protocols = Names(rule.Protocols),
            RoRule = Names(rule.RoRule),
            RwRule = Names(rule.RwRule),
            Superuser = Names(rule.Superuser),
            AnonymousUser = rule.AnonUid.ToString(CultureInfo.InvariantCulture),
        };
    }

    /// <summary>Converts a policy record and its rules to a core policy.</summary>
    public static ExportPolicy ToCore(string policyName, IEnumerable<ExportRuleRecord> rules, Func<string, long?>? resolveUserName = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        return new ExportPolicy(policyName, rules.Select(r => ToCore(r, resolveUserName)).OrderBy(r => r.Index).ToList());
    }

    internal static List<string> Names<T>(IEnumerable<T> values)
        where T : struct, Enum
        => values.Select(v => v.ToString().ToLowerInvariant()).Order(StringComparer.Ordinal).ToList();

    private static HashSet<SecurityFlavor> ParseFlavors(IEnumerable<string>? values)
    {
        var set = new HashSet<SecurityFlavor>();
        foreach (var v in values ?? Enumerable.Empty<string>())
        {
            if (!Flavors.TryGetValue(v, out var f))
            {
                throw new FormatException($"Unknown export rule security type '{v}'.");
            }

            set.Add(f);
        }

        return set;
    }

    private static HashSet<NfsProtocol> ParseProtocols(IEnumerable<string>? values)
    {
        var set = new HashSet<NfsProtocol>();
        foreach (var v in values ?? Enumerable.Empty<string>())
        {
            // cifs and other non NFS protocols do not affect NFS evaluation.
            if (Protocols.TryGetValue(v, out var p))
            {
                set.Add(p);
            }
        }

        if (values is null || !values.Any())
        {
            return new HashSet<NfsProtocol> { NfsProtocol.Any };
        }

        // Only non NFS protocols listed: an empty set, which never applies to an NFS request.
        return set;
    }

    private static long ParseAnon(string? value, Func<string, long?>? resolve)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return UnixIds.Nobody;
        }

        if (long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var uid))
        {
            return uid;
        }

        return resolve?.Invoke(value) ?? throw new FormatException($"Anonymous user '{value}' is not numeric and could not be resolved.");
    }
}
