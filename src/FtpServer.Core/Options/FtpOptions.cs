namespace FtpServer.Options;

public class FtpOptions
{
    public int Port { get; set; } = 21;

    public string RootPath { get; set; } = "/";

    public bool Ftps { get; set; } = false;

    public FtpFeatureOptions Features { get; set; } = new();

    public PassivePortRangeOptions PassivePortRange { get; set; } = new();
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