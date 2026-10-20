namespace FtpServer.Relay;

/// <summary>The "Relay" section of appsettings.json.</summary>
public sealed class RelayOptions
{
    /// <summary>
    /// Where clients connect, in plain FTP. 127.0.0.1 serves this machine only; another address of
    /// this machine, or empty for every interface, serves the network, which then carries passwords
    /// and files in the clear between the client and the relay.
    /// </summary>
    public string? ListenAddress { get; set; } = "127.0.0.1";

    public int Port { get; set; } = 21;

    /// <summary>The ports clients open their passive data connections to.</summary>
    public int PassivePortStart { get; set; } = 50300;

    public int PassivePortEnd { get; set; } = 50349;

    /// <summary>
    /// Pass MLSD and MLST on. Off by default: some clients list one directory per command when they
    /// can use MLSD, and only use a recursive listing (one LIST -R for a whole tree) when they cannot.
    /// </summary>
    public bool OfferMlsd { get; set; }

    /// <summary>
    /// The zone the client gets LIST times in. "Standard" (the default) is this machine's zone without
    /// daylight saving time, as clients that convert a server's LIST times with the standard offset
    /// all year read them. "Local" is this machine's zone with daylight saving time; anything else is
    /// a time zone id, such as "UTC".
    /// </summary>
    public string ListTimeZone { get; set; } = "Standard";

    /// <summary>
    /// Ask a server that offers DIRECT for a direct transfer before each RETR and STOR, so the file goes
    /// straight between the machine that holds it and the client. Whatever cannot be done directly goes
    /// through the server as usual.
    /// </summary>
    public bool Direct { get; set; } = true;

    /// <summary>How long a direct connection may take before the transfer goes through the server.</summary>
    public TimeSpan DirectConnectTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>How long the machine may take to answer, which includes writing an upload to its end.</summary>
    public TimeSpan DirectAnswerTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public UpstreamOptions Upstream { get; set; } = new();
}

/// <summary>The FTPS server every connection is relayed to.</summary>
public sealed class UpstreamOptions
{
    /// <summary>Required.</summary>
    public string Host { get; set; } = "";

    public int Port { get; set; } = 21;

    /// <summary>
    /// The SHA-1 thumbprint of a certificate to accept although it does not validate, such as a test
    /// server's self-signed one. Empty accepts only certificates that validate for <see cref="Host"/>.
    /// </summary>
    public string? CertificateThumbprint { get; set; }

    /// <summary>The zone the server writes LIST times in; the relay asks for them with -T and converts them.</summary>
    public string ListTimeZone { get; set; } = "UTC";

    /// <summary>How long to wait for a reply, which for a checksum of a large file includes reading it on the server.</summary>
    public int TimeoutSeconds { get; set; } = 120;
}
