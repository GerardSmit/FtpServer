using Microsoft.Extensions.Hosting;

namespace FtpServer;

internal class PassivePortProviderHostedService(PassivePortProvider passivePortProvider) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => passivePortProvider.StopAllAsync();
}
