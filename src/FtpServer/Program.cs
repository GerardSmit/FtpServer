using FtpServer;
using FtpServer.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args
});

builder.Logging.AddConsole();
builder.Configuration.AddCommandLine(args);
builder.Configuration.AddEnvironmentVariables();
builder.Configuration.AddJsonFile("appsettings.json", optional: true);
builder.Configuration.AddJsonFile("appsettings.Development.json", optional: true);

builder.Services.AddFtpServer();

builder.Services.AddOptions<FtpOptions>()
    .Bind(builder.Configuration);

var app = builder.Build();

app.Run();