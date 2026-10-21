using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace FtpServer.Direct;

/// <summary>
/// The addresses a side of a UDP tunnel may be reached at, written as <c>address:port</c> separated by
/// commas, an IPv6 address in brackets: <c>192.168.1.5:50123,[2001:db8::5]:50123,203.0.113.7:61001</c>.
/// </summary>
public static class Candidates
{
    /// <summary>At most this many are read from the other side, which is not trusted to be reasonable.</summary>
    public const int Max = 16;

    public static string Format(IEnumerable<IPEndPoint> endpoints) =>
        string.Join(',', endpoints.Select(x => x.Address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{x.Address}]:{x.Port.ToString(CultureInfo.InvariantCulture)}"
            : $"{x.Address}:{x.Port.ToString(CultureInfo.InvariantCulture)}"));

    /// <summary>The endpoints in <paramref name="text"/>; unreadable entries, host names and the excess are left out.</summary>
    public static List<IPEndPoint> Parse(string? text)
    {
        var endpoints = new List<IPEndPoint>();

        foreach (var entry in (text ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (endpoints.Count == Max)
            {
                break;
            }

            if (TryParseHostPort(entry, 0, out var host, out var port) && port > 0 && IPAddress.TryParse(host, out var address))
            {
                endpoints.Add(new IPEndPoint(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address, port));
            }
        }

        return endpoints;
    }

    /// <summary>Splits <c>host:port</c>, <c>[v6]:port</c>, a bare v6 address or a bare host; the port is <paramref name="defaultPort"/> when absent.</summary>
    public static bool TryParseHostPort(string text, int defaultPort, [NotNullWhen(true)] out string? host, out int port)
    {
        host = null;
        port = defaultPort;
        text = text.Trim();

        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']');

            if (close < 0)
            {
                return false;
            }

            host = text[1..close];

            if (close + 1 < text.Length)
            {
                if (text[close + 1] != ':' || !TryParsePort(text[(close + 2)..], out port))
                {
                    return false;
                }
            }

            return host.Length > 0;
        }

        var colon = text.LastIndexOf(':');

        // More than one colon without brackets is a bare IPv6 address.
        if (colon > 0 && text.IndexOf(':') == colon)
        {
            host = text[..colon];
            return TryParsePort(text[(colon + 1)..], out port) && host.Length > 0;
        }

        host = text;
        return host.Length > 0;
    }

    private static bool TryParsePort(string text, out int port) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;

    /// <summary>This machine's addresses: every interface that is up, without loopback, tunnels and link-local ones; IPv4 first.</summary>
    public static List<IPAddress> LocalAddresses()
    {
        var addresses = new List<IPAddress>();

        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                foreach (var unicast in adapter.GetIPProperties().UnicastAddresses)
                {
                    var address = unicast.Address;

                    if (IPAddress.IsLoopback(address) ||
                        address.AddressFamily == AddressFamily.InterNetwork && address.GetAddressBytes() is [169, 254, ..] ||
                        address.AddressFamily == AddressFamily.InterNetworkV6 && (address.IsIPv6LinkLocal || address.IsIPv6Multicast))
                    {
                        continue;
                    }

                    addresses.Add(address);
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        return addresses.Distinct().OrderBy(x => x.AddressFamily == AddressFamily.InterNetworkV6).ToList();
    }

    /// <summary>Private (RFC 1918), shared (100.64/10, as VPNs hand out) or unique local IPv6.</summary>
    public static bool IsPrivate(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return (address.GetAddressBytes()[0] & 0xFE) == 0xFC;
        }

        return address.GetAddressBytes() is [10, ..] or [192, 168, ..] or [172, >= 16 and <= 31, ..] or [100, >= 64 and <= 127, ..];
    }
}
