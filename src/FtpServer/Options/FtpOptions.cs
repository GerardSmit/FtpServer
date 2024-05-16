namespace FtpServer.Options;

public class FtpOptions
{
    public int Port { get; set; } = 21;

    public string RootPath { get; set; } = "/";

    public bool Ftps { get; set; } = false;
}
