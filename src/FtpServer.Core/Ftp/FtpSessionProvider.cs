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
        var rootPath = options.Value.Path;
        IFileSystem fileSystem = new PhysicalFileSystem();

        if (OperatingSystem.IsWindows() && rootPath.Length > 1 && rootPath[1] == ':')
        {
            // Convert Windows path to Unix path
            rootPath = fileSystem.ConvertPathFromInternal(rootPath).FullName;
        }

        if (rootPath != UPath.Root)
        {
            fileSystem = new SubFileSystem(fileSystem, rootPath);
        }

        return new FtpSession(pipe, provider, fileSystem);
    }
}
