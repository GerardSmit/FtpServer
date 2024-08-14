namespace FtpServer.Options;

public class FtpOptions
{
    public int Port { get; set; } = 21;

    public string Path { get; set; } = "/";

    public bool Ftps { get; set; }

    public bool Passive { get; set; }

    public FtpFeatureOptions Features { get; set; } = new();

    public PassivePortRangeOptions PassivePortRange { get; set; } = new();

    public FtpListOptions List { get; set; } = new();
}

public class FtpFeatureOptions
{
    public bool XCRC { get; set; } = true;

    public bool LISTR { get; set; } = true;
}

public class PassivePortRangeOptions
{
    public int Start { get; set; } = 50000;

    public int End { get; set; } = 50100;
}

public class FtpListOptions
{
    /// <summary>
    /// Limit of the recursion depth for the "LIST -R" command.
    /// </summary>
    public int RecursionLimit { get; set; } = 10;
}