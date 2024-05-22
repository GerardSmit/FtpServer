using System.IO.Pipelines;
using FtpServer.Options;
using Microsoft.Extensions.Options;
using Zio;
using Zio.FileSystems;

namespace FtpServer;

public class FtpSessionProvider(
    IServiceProvider provider,
    IOptions<FtpOptions> options)
{
    public FtpSession CreateSession(IDuplexPipe pipe)
    {
        var rootPath = options.Value.RootPath;
        IFileSystem fileSystem = new PhysicalFileSystem();

        if (rootPath != UPath.Root)
        {
            fileSystem = new SubFileSystem(fileSystem, options.Value.RootPath);
        }

        return new FtpSession(pipe, provider, fileSystem);
    }
}
