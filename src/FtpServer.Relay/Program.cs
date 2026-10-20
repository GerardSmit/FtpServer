using FtpServer.Relay;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// Plain FTP in, FTPS out: every client connection is relayed to an FTPS server over TLS.
// Runs in a console, or as a Windows service.
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,

    // A service starts in System32; appsettings.json is next to the program.
    ContentRootPath = AppContext.BaseDirectory
});

builder.Services.AddWindowsService(options => options.ServiceName = "FtpRelay");
builder.Services.AddFtpRelay(builder.Configuration.GetSection("Relay").Get<RelayOptions>() ?? new RelayOptions());

await builder.Build().RunAsync();
