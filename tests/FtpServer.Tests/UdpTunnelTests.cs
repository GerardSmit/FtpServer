using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FtpServer.Direct;

namespace FtpServer.Tests;

/// <summary>The UDP tunnel on one machine: punching, the stream over it, and TLS with pinned certificates on top.</summary>
public class UdpTunnelTests
{
    private static readonly UdpTunnelOptions Local = new() { UseStun = false, IncludeLoopback = true };

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static async Task<(Stream Accepted, Stream Connected)> PairAsync(string key = "0123456789abcdef")
    {
        var listening = await UdpTunnel.OpenAsync(Local, TestContext.Current.CancellationToken);
        var dialing = await UdpTunnel.OpenAsync(Local, TestContext.Current.CancellationToken);

        var accept = listening.AcceptAsync(dialing.Candidates, key, Timeout, TestContext.Current.CancellationToken);
        var connect = dialing.ConnectAsync(listening.Candidates, key, Timeout, TestContext.Current.CancellationToken);

        var connected = await connect;

        // The accepting side binds to the connection once it speaks, as the first write does.
        await connected.WriteAsync("x"u8.ToArray(), TestContext.Current.CancellationToken);
        var accepted = await accept;

        var one = new byte[1];
        Assert.Equal(1, await accepted.ReadAsync(one, TestContext.Current.CancellationToken));
        return (accepted, connected);
    }

    [Fact]
    public async Task Data_arrives_whole_and_in_order_both_ways()
    {
        var (accepted, connected) = await PairAsync();
        var outbound = RandomNumberGenerator.GetBytes(32 * 1024 * 1024 + 123);
        var inbound = RandomNumberGenerator.GetBytes(3 * 1024 * 1024 + 7);

        await using (accepted)
        await using (connected)
        {
            var sending = Task.Run(async () =>
            {
                await connected.WriteAsync(outbound, TestContext.Current.CancellationToken);
                await accepted.WriteAsync(inbound, TestContext.Current.CancellationToken);
            });

            var received = await ReadExactlyAsync(accepted, outbound.Length);
            var answered = await ReadExactlyAsync(connected, inbound.Length);
            await sending;

            Assert.True(received.AsSpan().SequenceEqual(outbound));
            Assert.True(answered.AsSpan().SequenceEqual(inbound));
        }
    }

    [Fact]
    public async Task The_end_of_the_stream_is_told()
    {
        var (accepted, connected) = await PairAsync();

        await connected.WriteAsync("last"u8.ToArray(), TestContext.Current.CancellationToken);
        await connected.DisposeAsync();

        Assert.Equal("last"u8.ToArray(), await ReadExactlyAsync(accepted, 4));
        Assert.Equal(0, await accepted.ReadAsync(new byte[16], TestContext.Current.CancellationToken));
        await accepted.DisposeAsync();
    }

    [Fact]
    public async Task Another_key_is_not_accepted()
    {
        var listening = await UdpTunnel.OpenAsync(Local, TestContext.Current.CancellationToken);
        var dialing = await UdpTunnel.OpenAsync(Local, TestContext.Current.CancellationToken);

        var accept = listening.AcceptAsync(dialing.Candidates, "0123456789abcdef", TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        var connect = dialing.ConnectAsync(listening.Candidates, "fedcba9876543210", TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<IOException>(() => connect);
        await Assert.ThrowsAsync<IOException>(() => accept);
    }

    [Fact]
    public async Task Tls_with_pinned_certificates_runs_over_it()
    {
        using var server = CreateCertificate();
        using var client = CreateCertificate();
        var (accepted, connected) = await PairAsync();

        await using var serverTls = new SslStream(accepted);
        await using var clientTls = new SslStream(connected);

        var serverSide = serverTls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = server,
            ClientCertificateRequired = true,
            RemoteCertificateValidationCallback = (_, certificate, _, _) => Pinned(certificate, client)
        }, TestContext.Current.CancellationToken);

        await clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "direct",
            LocalCertificateSelectionCallback = (_, _, _, _, _) => client,
            RemoteCertificateValidationCallback = (_, certificate, _, _) => Pinned(certificate, server)
        }, TestContext.Current.CancellationToken);

        await serverSide;

        var payload = RandomNumberGenerator.GetBytes(1024 * 1024);
        await clientTls.WriteAsync(payload, TestContext.Current.CancellationToken);
        Assert.True((await ReadExactlyAsync(serverTls, payload.Length)).AsSpan().SequenceEqual(payload));
    }

    [Fact]
    public async Task Nothing_listening_gives_up_within_the_timeout()
    {
        var dialing = await UdpTunnel.OpenAsync(Local, TestContext.Current.CancellationToken);
        var started = DateTime.UtcNow;

        await Assert.ThrowsAsync<IOException>(() =>
            dialing.ConnectAsync([new IPEndPoint(IPAddress.Loopback, 9)], "0123456789abcdef", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken));

        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData("192.168.1.5:50123,[2001:db8::5]:50123, 203.0.113.7:61001", 3)]
    [InlineData("host.example:80,1.2.3.4,::1,[::1]:22", 1)]
    [InlineData("", 0)]
    public void Candidates_are_read_without_host_names_or_missing_ports(string text, int count)
    {
        var parsed = Candidates.Parse(text);

        Assert.Equal(count, parsed.Count);
        Assert.Equal(parsed, Candidates.Parse(Candidates.Format(parsed)));
    }

    [Fact]
    public void A_stun_answer_gives_the_mapped_address()
    {
        var transaction = RandomNumberGenerator.GetBytes(12);

        // XOR-MAPPED-ADDRESS for 203.0.113.7:61001, as RFC 5389 encodes it.
        var answer = new byte[32];
        BinaryPrimitives.WriteUInt16BigEndian(answer, 0x0101);
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(2), 12);
        BinaryPrimitives.WriteUInt32BigEndian(answer.AsSpan(4), 0x2112A442);
        transaction.CopyTo(answer, 8);
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(20), 0x0020);
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(22), 8);
        answer[25] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(26), (ushort)(61001 ^ 0x2112));
        var address = IPAddress.Parse("203.0.113.7").GetAddressBytes();
        byte[] cookie = [0x21, 0x12, 0xA4, 0x42];

        for (var i = 0; i < 4; i++)
        {
            answer[28 + i] = (byte)(address[i] ^ cookie[i]);
        }

        var parsed = StunClient.Parse(answer);

        Assert.NotNull(parsed);
        Assert.Equal(Convert.ToHexString(transaction), parsed.Value.Transaction);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.7"), 61001), parsed.Value.Mapped);
        Assert.Null(StunClient.Parse(answer.AsSpan(0, 19)));
    }

    private static bool Pinned(X509Certificate? certificate, X509Certificate2 expected) =>
        certificate is not null &&
        CryptographicOperations.FixedTimeEquals(certificate.GetCertHash(HashAlgorithmName.SHA256), expected.GetCertHash(HashAlgorithmName.SHA256));

    private static X509Certificate2 CreateCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=direct", key, HashAlgorithmName.SHA256);
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null);
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int length)
    {
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, TestContext.Current.CancellationToken);
        return buffer;
    }
}
