using System.Collections.Concurrent;
using LiteNetLib;

namespace FtpServer.Direct;

/// <summary>
/// A reliable byte stream over one LiteNetLib connection. Writes go out in packets of at most one
/// datagram, spread in turn over <see cref="Channels"/> reliable ordered channels so more is in flight
/// than one channel's window allows, and are read back in the same turn. A packet starts with its kind.
/// </summary>
internal sealed class UdpStream : Stream
{
    public const byte Channels = 32;

    /// <summary>Packets sent and not yet acknowledged, over all channels; below LiteNetLib's own window per channel.</summary>
    private const int Window = Channels * 48;

    private const byte Data = 0;
    private const byte End = 1;
    private const byte Hello = 2;

    private static readonly object Delivered = new();

    private readonly NetManager _manager;
    private readonly ConcurrentQueue<byte[]>[] _incoming = Enumerable.Range(0, Channels).Select(_ => new ConcurrentQueue<byte[]>()).ToArray();
    private readonly SemaphoreSlim _arrived = new(0);
    private readonly SemaphoreSlim _window = new(Window, Window);
    private readonly TaskCompletionSource _bound = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private NetPeer? _peer;
    private long _readSequence;
    private long _writeSequence;
    private byte[]? _current;
    private int _offset;
    private bool _ended;
    private volatile bool _closed;
    private int _disposed;

    public UdpStream(NetManager manager, EventBasedNetListener events)
    {
        _manager = manager;

        events.NetworkReceiveEvent += (peer, reader, channel, _) =>
        {
            var packet = reader.GetRemainingBytes();

            if (packet.Length == 0 || channel >= Channels)
            {
                return;
            }

            // The listening side takes the first connection that speaks; another is not listened to.
            if (Volatile.Read(ref _peer) is null)
            {
                Bind(peer);
            }

            if (peer != _peer || packet[0] == Hello)
            {
                return;
            }

            _incoming[channel].Enqueue(packet);
            _arrived.Release();
        };

        events.DeliveryEvent += (peer, userData) =>
        {
            if (peer == _peer && userData == Delivered)
            {
                _window.Release();
            }
        };

        events.PeerDisconnectedEvent += (peer, _) =>
        {
            if (peer == _peer)
            {
                _closed = true;
                _arrived.Release();

                // Wakes a writer waiting for room; it then finds the connection closed.
                if (Window - _window.CurrentCount is > 0 and var missing)
                {
                    _window.Release(missing);
                }
            }
        };
    }

    public bool IsBound => Volatile.Read(ref _peer) is not null;

    public Task Bound => _bound.Task;

    public void Bind(NetPeer peer)
    {
        if (Interlocked.CompareExchange(ref _peer, peer, null) is null)
        {
            _bound.TrySetResult();
        }
    }

    public void SendHello()
    {
        _peer!.Send([Hello], 0, DeliveryMethod.ReliableOrdered);
        _manager.TriggerUpdate();
    }

    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanSeek => false;

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            if (_current is not null && _offset < _current.Length)
            {
                var count = Math.Min(buffer.Length, _current.Length - _offset);
                _current.AsMemory(_offset, count).CopyTo(buffer);
                _offset += count;
                return count;
            }

            if (_ended)
            {
                return 0;
            }

            // Packet n came on channel n % Channels, and each channel keeps its own order.
            if (_incoming[_readSequence % Channels].TryDequeue(out var packet))
            {
                _readSequence++;

                if (packet[0] == End)
                {
                    _ended = true;
                    return 0;
                }

                _current = packet;
                _offset = 1;
                continue;
            }

            if (_closed)
            {
                throw new IOException("The UDP connection was lost.");
            }

            await _arrived.WaitAsync(cancellationToken);
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var peer = _peer ?? throw new InvalidOperationException("Not connected.");
        var size = peer.GetMaxSinglePacketSize(DeliveryMethod.ReliableOrdered) - 1;

        while (!buffer.IsEmpty)
        {
            var count = Math.Min(size, buffer.Length);
            var packet = new byte[count + 1];
            packet[0] = Data;
            buffer.Span[..count].CopyTo(packet.AsSpan(1));
            await SendAsync(peer, packet, cancellationToken);
            buffer = buffer[count..];
        }

        _manager.TriggerUpdate();
    }

    private async Task SendAsync(NetPeer peer, byte[] packet, CancellationToken cancellationToken)
    {
        await _window.WaitAsync(cancellationToken);

        if (_closed)
        {
            throw new IOException("The UDP connection was lost.");
        }

        peer.SendWithDeliveryEvent(packet, (byte)(_writeSequence++ % Channels), DeliveryMethod.ReliableOrdered, Delivered);
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        _manager.TriggerUpdate();
        return Task.CompletedTask;
    }

    /// <summary>Tells the other side nothing more follows, and waits until all that was sent arrived.</summary>
    private async Task CompleteAsync()
    {
        if (_peer is not { } peer || _closed)
        {
            return;
        }

        using var waiting = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            await SendAsync(peer, [End], waiting.Token);
            _manager.TriggerUpdate();

            while (_window.CurrentCount < Window && !_closed)
            {
                await Task.Delay(5, waiting.Token);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException)
        {
            // Gone or too slow: whatever was not confirmed by now is the reader's loss, which it notices.
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        await CompleteAsync();
        _manager.Stop(sendDisconnectMessages: true);
        _closed = true;
        _arrived.Release();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush() => _manager.TriggerUpdate();

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
