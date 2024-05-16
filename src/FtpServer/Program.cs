// See https://aka.ms/new-console-template for more information

using FtpServer;
using FtpServer.Handlers;
using FtpServer.IO;
using FtpServer.Options;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
{
    Args = args
});

builder.Logging.AddConsole();
builder.Configuration.AddCommandLine(args);
builder.Configuration.AddEnvironmentVariables();
builder.Configuration.AddJsonFile("appsettings.json", optional: true);
builder.Configuration.AddJsonFile("appsettings.Development.json", optional: true);

builder.Services.AddSingleton<CertificateProvider>();
builder.Services.AddSingleton<PermissionProvider>();
builder.Services.AddSingleton<FtpSessionProvider>();
builder.Services.AddSingleton<FtpCommandHandler, DefaultFtpCommandHandler>();

builder.Services.AddOptions<FtpOptions>()
    .Bind(builder.Configuration);

builder.WebHost.UseKestrel((context, options) =>
{
    var ftpOptions = options.ApplicationServices.GetRequiredService<IOptions<FtpOptions>>().Value;

    options.ListenAnyIP(ftpOptions.Port, listenOptions =>
    {
        listenOptions.UseConnectionLogging();
        listenOptions.UseConnectionHandler<FtpConnectionHandler>();
    });
});

var app = builder.Build();

app.Run();