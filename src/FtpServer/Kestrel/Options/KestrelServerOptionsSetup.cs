// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

namespace FtpServer.Kestrel.Options;

internal sealed class KestrelServerOptionsSetup(IServiceProvider services) : IConfigureOptions<KestrelServerOptions>
{
    public void Configure(KestrelServerOptions options)
    {
        options.ApplicationServices = services;
    }
}
