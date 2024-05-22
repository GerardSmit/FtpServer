using System.IO.Pipelines;
using FtpServer.Options;
using Microsoft.Extensions.Options;
using Zio.FileSystems;

namespace FtpServer;

public class FtpSessionProvider(
    IServiceProvider provider,
    IOptions<FtpOptions> options)
{
    public FtpSession CreateSession(IDuplexPipe pipe)
    {
        var fileSystem = new SubFileSystem(new PhysicalFileSystem(), options.Value.RootPath);

        return new FtpSession(pipe, provider, fileSystem);
    }
}
