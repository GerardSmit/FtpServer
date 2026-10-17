using System.Net;
using FtpServer.Handlers;
using FtpServer.Options;
using Microsoft.Extensions.Logging.Abstractions;

namespace FtpServer.Tests;

public class PassiveModeTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.1.10")]
    [InlineData("169.254.10.10")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1234")]
    public void Private_and_local_addresses_are_recognised(string address)
    {
        Assert.True(DefaultFtpCommandHandler.IsPrivateOrLocal(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("172.15.0.1")]
    [InlineData("172.32.0.1")]
    [InlineData("193.168.1.1")]
    [InlineData("2001:db8::1")]
    public void Public_addresses_are_not_flagged_private(string address)
    {
        Assert.False(DefaultFtpCommandHandler.IsPrivateOrLocal(IPAddress.Parse(address)));
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
