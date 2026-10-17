using System.Collections.Concurrent;
using FtpServer.IO.Results;
using Zio;

namespace FtpServer.IO;

public sealed partial class PermissionProvider
{
    /// <summary>Bounds the name caches; a host has far fewer distinct owners than this.</summary>
    private const int MaxCachedNames = 4096;

    private readonly ConcurrentDictionary<string, string> _accountNames = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<uint, string> _userNames = new();
    private readonly ConcurrentDictionary<uint, string> _groupNames = new();

    /// <param name="includeNames">
    /// Whether the owner and group names are wanted. Resolving them is the expensive part, and
    /// the mode bits alone need none of it.
    /// </param>
    public FilePermissionResult GetFilePermissions(in FileSystemItem item, string path, bool includeNames = true)
    {
        return OperatingSystem.IsWindows()
            ? GetFilePermissionsWindows(item, path, includeNames)
            : GetFilePermissionsUnix(item, path, includeNames);
    }

    /// <remarks>
    /// The names are not expired: an account rename is rare, and the worst a stale entry does is
    /// show the old name in a listing until the server restarts. Clearing when full keeps a host
    /// with an unusual number of owners from growing the cache without bound.
    /// </remarks>
    private static void CacheName<TKey>(ConcurrentDictionary<TKey, string> cache, TKey key, string name)
        where TKey : notnull
    {
        if (cache.Count >= MaxCachedNames)
        {
            cache.Clear();
        }

        cache[key] = name;
    }
}
