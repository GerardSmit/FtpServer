using System.Net;
using FtpServer.Handlers;
using FtpServer.Options;
using Microsoft.Extensions.Logging.Abstractions;

namespace FtpServer.Tests;

public class PassiveModeTests
{
    [Theory]
    [InlineData("203.0.113.7")]
    [InlineData("192.168.10.210")]
    [InlineData("172.18.0.1")]
    [InlineData("::ffff:192.168.10.210")]
    public void A_public_address_is_advertised_to_lan_and_internet_peers(string peer)
    {
        // Behind Docker the local address is the container's; a LAN client cannot reach it either.
        var advertised = DefaultFtpCommandHandler.SelectAdvertisedAddress(
            IPAddress.Parse("::ffff:172.18.0.2"), IPAddress.Parse(peer), "192.168.10.73");

        Assert.Equal(IPAddress.Parse("192.168.10.73"), advertised);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::ffff:127.0.0.1")]
    public void A_loopback_peer_keeps_the_local_address(string peer)
    {
        var advertised = DefaultFtpCommandHandler.SelectAdvertisedAddress(
            IPAddress.Parse("::ffff:127.0.0.1"), IPAddress.Parse(peer), "192.168.10.73");

        Assert.Equal(IPAddress.Parse("127.0.0.1"), advertised);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-address")]
    [InlineData("2001:db8::1")]
    public void Without_a_usable_public_address_the_local_one_is_advertised(string? configured)
    {
        var advertised = DefaultFtpCommandHandler.SelectAdvertisedAddress(
            IPAddress.Parse("::ffff:10.0.0.5"), IPAddress.Parse("203.0.113.7"), configured);

        Assert.Equal(IPAddress.Parse("10.0.0.5"), advertised);
    }

    [Fact]
    public async Task Rented_passive_ports_stay_inside_the_configured_range()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new FtpOptions
        {
            PassivePortRange = new PassivePortRangeOptions { Start = 51000, End = 51009 },
        });

        var provider = new PassivePortProvider(options, NullLogger<PassiveSocket>.Instance);

        try
        {
            var owners = new List<PassiveSocketOwner>();

            // One peer address may hold at most one slot per port, so ten distinct peers can
            // drain the whole range; every rented port must fall inside it.
            for (var i = 0; i < 10; i++)
            {
                var owner = await provider.TryRentAsync(IPAddress.Parse($"203.0.113.{i + 1}"));
                Assert.NotNull(owner);
                Assert.InRange(owner!.Port, 51000, 51009);
                owners.Add(owner);
            }

            foreach (var owner in owners)
            {
                owner.Dispose();
            }
        }
        finally
        {
            await provider.StopAllAsync();
        }
    }
}
