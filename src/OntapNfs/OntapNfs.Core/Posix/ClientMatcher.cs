using System.Net;
using System.Net.Sockets;

namespace OntapNfs.Core.Posix;

/// <summary>
/// Matches an NFS client against ONTAP <c>clientmatch</c> entries: a single IP,
/// a CIDR block, a host name, a domain suffix beginning with a dot, or a comma
/// separated list of these. Netgroups (<c>@name</c>) are not resolved here and
/// never match.
/// </summary>
public static class ClientMatcher
{
    /// <summary>True when any entry matches the client.</summary>
    public static bool Matches(IEnumerable<string> clientMatch, NfsClient client)
    {
        ArgumentNullException.ThrowIfNull(clientMatch);
        ArgumentNullException.ThrowIfNull(client);
        return clientMatch
            .SelectMany(m => m.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Any(m => MatchesOne(m, client));
    }

    /// <summary>True when one entry matches the client.</summary>
    public static bool MatchesOne(string match, NfsClient client)
    {
        ArgumentNullException.ThrowIfNull(match);
        ArgumentNullException.ThrowIfNull(client);
        var m = match.Trim();
        if (m.Length == 0 || m.StartsWith('@'))
        {
            return false;
        }

        if (m.Contains('/', StringComparison.Ordinal))
        {
            return TryParseCidr(m, out var network, out var prefix) && InCidr(Normalize(client.Address), network, prefix);
        }

        if (IPAddress.TryParse(m, out var ip))
        {
            return Normalize(ip).Equals(Normalize(client.Address));
        }

        if (client.HostName is null)
        {
            return false;
        }

        var host = client.HostName.TrimEnd('.');
        if (m.StartsWith('.'))
        {
            return host.EndsWith(m, StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(host, m.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Parses <c>a.b.c.d/n</c> or an IPv6 prefix.</summary>
    public static bool TryParseCidr(string text, out IPAddress network, out int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(text);
        network = IPAddress.None;
        prefixLength = 0;
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        if (slash <= 0
            || !IPAddress.TryParse(text.AsSpan(0, slash), out var addr)
            || !int.TryParse(text.AsSpan(slash + 1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var prefix))
        {
            return false;
        }

        addr = Normalize(addr);
        var max = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix > max)
        {
            return false;
        }

        network = addr;
        prefixLength = prefix;
        return true;
    }

    private static bool InCidr(IPAddress address, IPAddress network, int prefixLength)
    {
        if (address.AddressFamily != network.AddressFamily)
        {
            return false;
        }

        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (a[i] != n[i])
            {
                return false;
            }
        }

        var remaining = prefixLength % 8;
        if (remaining == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remaining));
        return (a[fullBytes] & mask) == (n[fullBytes] & mask);
    }

    private static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
