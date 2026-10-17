using System.Collections.Concurrent;
using FtpServer.Handlers;
using Zio;

namespace FtpServer.IO;

/// <summary>
/// Remembers what a file measures once translated to ASCII, so repeating the question is cheap.
/// </summary>
/// <remarks>
/// An ASCII SIZE has to be counted rather than looked up (RFC 3659 section 4), and a resuming
/// client asks twice. Entries are keyed by the length and modification time they were measured
/// from, so a file that changes is measured again rather than answered from a stale count.
/// </remarks>
public sealed class AsciiSizeCache
{
    /// <summary>
    /// Entries kept before the map is cleared wholesale, which avoids tracking recency for what is
    /// only an optimisation.
    /// </summary>
    private const int Capacity = 512;

    private readonly ConcurrentDictionary<Key, long> _entries = new();

    private readonly record struct Key(IFileSystem FileSystem, UPath Path, long Length, DateTime LastWriteTime);

    public async ValueTask<long> GetAsync(IFileSystem fileSystem, UPath path, long length, CancellationToken token)
    {
        var key = new Key(fileSystem, path, length, fileSystem.GetLastWriteTime(path));

        if (_entries.TryGetValue(key, out var cached))
        {
            return cached;
        }

        await using var stream = fileSystem.OpenFile(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var measured = await AsciiTransfer.MeasureAsync(stream, token);

        if (_entries.Count >= Capacity)
        {
            _entries.Clear();
        }

        _entries[key] = measured;
        return measured;
    }
}
