using System.Net;
using OntapNfs.Core.Posix;
using Xunit;

namespace OntapNfs.Tests.Core;

public sealed class ExportPolicyTests
{
    private static readonly NfsClient AppHost = new(IPAddress.Parse("10.20.1.15"), "app01.prod.example.com");
    private static readonly NfsClient Other = new(IPAddress.Parse("192.168.9.9"), "laptop.corp.example.org");

    private static HashSet<SecurityFlavor> F(params SecurityFlavor[] f) => new(f);

    private static ExportRule Rule(int index, string match, HashSet<SecurityFlavor> ro, HashSet<SecurityFlavor> rw, HashSet<SecurityFlavor> su, long anon = UnixIds.Nobody, params NfsProtocol[] protocols)
        => new(index, new[] { match }, ro, rw, su, anon, new HashSet<NfsProtocol>(protocols.Length == 0 ? new[] { NfsProtocol.Any } : protocols));

    [Theory]
    [InlineData("10.20.0.0/16", true)]
    [InlineData("10.20.1.15", true)]
    [InlineData("10.20.1.15/32", true)]
    [InlineData("10.20.1.0/25", true)]
    [InlineData("10.20.1.128/25", false)]
    [InlineData("0.0.0.0/0", true)]
    [InlineData("app01.prod.example.com", true)]
    [InlineData("APP01.prod.example.com.", true)]
    [InlineData(".prod.example.com", true)]
    [InlineData(".example.org", false)]
    [InlineData("@appservers", false)]
    [InlineData("10.30.0.0/16,10.20.1.15", true)]
    [InlineData("10.20.0.0/33", false)]
    [InlineData("not-an-ip/8", false)]
    [InlineData("", false)]
    public void Client_match(string match, bool expected)
        => Assert.Equal(expected, ClientMatcher.Matches(new[] { match }, AppHost));

    [Fact]
    public void Client_match_ipv6_and_mapped_ipv4()
    {
        var v6 = new NfsClient(IPAddress.Parse("fd00:10::25"));
        Assert.True(ClientMatcher.MatchesOne("fd00:10::/32", v6));
        Assert.False(ClientMatcher.MatchesOne("10.0.0.0/8", v6));
        var mapped = new NfsClient(IPAddress.Parse("::ffff:10.20.1.15"));
        Assert.True(ClientMatcher.MatchesOne("10.20.0.0/16", mapped));
        Assert.True(ClientMatcher.MatchesOne("10.20.1.15", mapped));
        Assert.False(ClientMatcher.MatchesOne("host.example.com", new NfsClient(IPAddress.Loopback)));
        Assert.True(ClientMatcher.MatchesOne("::/0", v6));
    }

    [Fact]
    public void First_matching_rule_by_index_wins()
    {
        var policy = new ExportPolicy("apps", new[]
        {
            Rule(2, "0.0.0.0/0", F(SecurityFlavor.Sys), F(SecurityFlavor.Never), F(SecurityFlavor.None)),
            Rule(1, "10.20.0.0/16", F(SecurityFlavor.Sys), F(SecurityFlavor.Sys), F(SecurityFlavor.None)),
        });
        var d = ExportAccessEvaluator.Evaluate(policy, AppHost, 1201, 1201);
        Assert.Equal(ExportAccess.ReadWrite, d.Access);
        Assert.Equal(1, d.RuleIndex);
        Assert.Equal(1201, d.EffectiveUid);
        Assert.False(d.MappedToAnonymous);

        var o = ExportAccessEvaluator.Evaluate(policy, Other, 1201, 1201);
        Assert.Equal(ExportAccess.ReadOnly, o.Access);
        Assert.Equal(2, o.RuleIndex);
    }

    [Fact]
    public void No_match_denies()
    {
        var policy = new ExportPolicy("apps", new[] { ExportRule.ForSys(1, "10.20.0.0/16", readWrite: true) });
        var d = ExportAccessEvaluator.Evaluate(policy, Other, 1201, 1201);
        Assert.Equal(ExportAccess.None, d.Access);
        Assert.Null(d.RuleIndex);
        Assert.Contains("no rule", d.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Root_is_squashed_to_anon_unless_superuser_allows()
    {
        var squash = new ExportPolicy("p", new[] { ExportRule.ForSys(1, "0.0.0.0/0", readWrite: true) });
        var d = ExportAccessEvaluator.Evaluate(squash, AppHost, 0, 0);
        Assert.True(d.RootSquashed);
        Assert.True(d.MappedToAnonymous);
        Assert.Equal(65534, d.EffectiveUid);
        Assert.Equal(65534, d.EffectiveGid);
        Assert.Contains("root squashed", d.Reason, StringComparison.Ordinal);

        var keep = new ExportPolicy("p", new[] { ExportRule.ForSys(1, "0.0.0.0/0", readWrite: true, rootSquash: false) });
        var k = ExportAccessEvaluator.Evaluate(keep, AppHost, 0, 0);
        Assert.False(k.RootSquashed);
        Assert.Equal(0, k.EffectiveUid);

        var anySu = new ExportPolicy("p", new[] { Rule(1, "0.0.0.0/0", F(SecurityFlavor.Sys), F(SecurityFlavor.Sys), F(SecurityFlavor.Any)) });
        Assert.Equal(0, ExportAccessEvaluator.Evaluate(anySu, AppHost, 0, 0).EffectiveUid);
    }

    [Fact]
    public void Anon_65535_denies_squashed_root()
    {
        var policy = new ExportPolicy("p", new[] { ExportRule.ForSys(1, "0.0.0.0/0", readWrite: true, anonUid: 65535) });
        var d = ExportAccessEvaluator.Evaluate(policy, AppHost, 0, 0);
        Assert.Equal(ExportAccess.None, d.Access);
        Assert.Contains("65535", d.Reason, StringComparison.Ordinal);
        Assert.Equal(ExportAccess.ReadWrite, ExportAccessEvaluator.Evaluate(policy, AppHost, 1201, 1201).Access);
    }

    [Fact]
    public void Rorule_none_maps_to_anonymous_and_rorule_krb5_denies_sys()
    {
        var none = new ExportPolicy("p", new[] { Rule(1, "0.0.0.0/0", F(SecurityFlavor.Krb5, SecurityFlavor.None), F(SecurityFlavor.Krb5), F(SecurityFlavor.None)) });
        var d = ExportAccessEvaluator.Evaluate(none, AppHost, 1201, 1201);
        Assert.Equal(ExportAccess.ReadOnly, d.Access);
        Assert.True(d.MappedToAnonymous);
        Assert.False(d.RootSquashed);
        Assert.Contains("rorule none", d.Reason, StringComparison.Ordinal);

        var krb = new ExportPolicy("p", new[] { Rule(1, "0.0.0.0/0", F(SecurityFlavor.Krb5), F(SecurityFlavor.Krb5), F(SecurityFlavor.None)) });
        Assert.Equal(ExportAccess.None, ExportAccessEvaluator.Evaluate(krb, AppHost, 1201, 1201).Access);
    }

    [Fact]
    public void Rwrule_none_reports_anonymous_writes_and_never_blocks_listed_flavour()
    {
        var p = new ExportPolicy("p", new[] { Rule(1, "0.0.0.0/0", F(SecurityFlavor.Sys), F(SecurityFlavor.None), F(SecurityFlavor.None)) });
        var d = ExportAccessEvaluator.Evaluate(p, AppHost, 1201, 1201);
        Assert.Equal(ExportAccess.ReadWrite, d.Access);
        Assert.Contains("rwrule none", d.Reason, StringComparison.Ordinal);

        var never = new ExportPolicy("p", new[] { Rule(1, "0.0.0.0/0", F(SecurityFlavor.Any), F(SecurityFlavor.Never), F(SecurityFlavor.None)) });
        Assert.Equal(ExportAccess.ReadOnly, ExportAccessEvaluator.Evaluate(never, AppHost, 1201, 1201).Access);
    }

    [Fact]
    public void Anon_zero_is_reported()
    {
        var p = new ExportPolicy("p", new[] { ExportRule.ForSys(1, "0.0.0.0/0", readWrite: true, anonUid: 0) });
        var d = ExportAccessEvaluator.Evaluate(p, AppHost, 0, 0);
        Assert.Contains("anon=0", d.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Protocol_filter_skips_rules()
    {
        var p = new ExportPolicy("p", new[]
        {
            Rule(1, "0.0.0.0/0", F(SecurityFlavor.Sys), F(SecurityFlavor.Sys), F(SecurityFlavor.None), UnixIds.Nobody, NfsProtocol.Nfs4),
            Rule(2, "0.0.0.0/0", F(SecurityFlavor.Sys), F(SecurityFlavor.Never), F(SecurityFlavor.None), UnixIds.Nobody, NfsProtocol.Nfs),
        });
        Assert.Equal(2, ExportAccessEvaluator.Evaluate(p, AppHost, 1, 1).RuleIndex);
        Assert.Equal(1, ExportAccessEvaluator.Evaluate(p, AppHost, 1, 1, protocol: NfsProtocol.Nfs4).RuleIndex);

        var empty = new ExportRule(1, new[] { "0.0.0.0/0" }, F(SecurityFlavor.Sys), F(SecurityFlavor.Sys), F(), 65534, new HashSet<NfsProtocol>());
        Assert.False(empty.AppliesTo(NfsProtocol.Nfs3));
    }

    [Fact]
    public void Same_effect_ignores_index_and_case()
    {
        var a = ExportRule.ForSys(1, "App01.example.com", readWrite: true);
        var b = ExportRule.ForSys(7, "app01.example.com ", readWrite: true);
        Assert.True(a.SameEffectAs(b));
        Assert.False(a.SameEffectAs(ExportRule.ForSys(1, "App01.example.com", readWrite: false)));
        Assert.Equal("x", ExportRule.Normalize(" X "));
    }

    [Fact]
    public void Unix_group_convenience_constructor()
        => Assert.Empty(new UnixGroup("g", 1).Members);
}
