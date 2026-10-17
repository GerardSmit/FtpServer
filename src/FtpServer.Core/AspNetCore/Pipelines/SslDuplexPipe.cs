// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO.Pipelines;
using System.Net.Security;

namespace FtpServer.Pipelines;

internal sealed class SslDuplexPipe : DuplexPipeStreamAdapter<SslStream>
{
    public SslDuplexPipe(IDuplexPipe transport, StreamPipeReaderOptions readerOptions, StreamPipeWriterOptions writerOptions)
        // The inner stream is the adapter itself, whose Dispose is not supported: letting
        // SslStream close it turns an ordinary teardown into an exception.
        : this(transport, readerOptions, writerOptions, s => new SslStream(s, leaveInnerStreamOpen: true))
    {
    }

    public SslDuplexPipe(IDuplexPipe transport, StreamPipeReaderOptions readerOptions, StreamPipeWriterOptions writerOptions, Func<Stream, SslStream> factory) :
        base(transport, readerOptions, writerOptions, factory)
    {
    }
}
