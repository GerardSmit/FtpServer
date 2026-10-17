using System.Diagnostics;
using System.Net;
using System.Text;

namespace FtpServer.Tests;

/// <summary>
/// Drives the server with clients that were written by somebody else, so the protocol is judged
/// by an independent implementation rather than by the test harness that shares its assumptions.
/// </summary>
public class RealClientTests
{
    [Fact]
    public async Task DotNet_FtpWebRequest_can_download_list_and_upload()
    {
        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("readme.txt", "content for the built-in client");

        var baseUri = $"ftp://127.0.0.1:{server.Port}/";
        var credentials = new NetworkCredential("anonymous", "a@b.c");

#pragma warning disable SYSLIB0014 // FtpWebRequest is obsolete but is still what many callers use.
        var download = (FtpWebRequest)WebRequest.Create(baseUri + "readme.txt");
        download.Method = WebRequestMethods.Ftp.DownloadFile;
        download.Credentials = credentials;
        download.UsePassive = true;

        using (var response = (FtpWebResponse)await download.GetResponseAsync())
        using (var reader = new StreamReader(response.GetResponseStream()))
        {
            Assert.Equal("content for the built-in client", await reader.ReadToEndAsync());
        }

        // ListDirectory issues NLST, which used to answer 502.
        var list = (FtpWebRequest)WebRequest.Create(baseUri);
        list.Method = WebRequestMethods.Ftp.ListDirectory;
        list.Credentials = credentials;

        using (var response = (FtpWebResponse)await list.GetResponseAsync())
        using (var reader = new StreamReader(response.GetResponseStream()))
        {
            Assert.Contains("readme.txt", await reader.ReadToEndAsync());
        }

        // GetFileSize issues SIZE, which used to answer 502 and yield ContentLength -1.
        var size = (FtpWebRequest)WebRequest.Create(baseUri + "readme.txt");
        size.Method = WebRequestMethods.Ftp.GetFileSize;
        size.Credentials = credentials;

        using (var response = (FtpWebResponse)await size.GetResponseAsync())
        {
            Assert.Equal(31, response.ContentLength);
        }

        var upload = (FtpWebRequest)WebRequest.Create(baseUri + "uploaded.txt");
        upload.Method = WebRequestMethods.Ftp.UploadFile;
        upload.Credentials = credentials;

        await using (var stream = await upload.GetRequestStreamAsync())
        {
            await stream.WriteAsync("round trip"u8.ToArray());
        }

        using (var response = (FtpWebResponse)await upload.GetResponseAsync())
        {
            Assert.Equal(FtpStatusCode.ClosingData, response.StatusCode);
        }
#pragma warning restore SYSLIB0014

        Assert.Equal("round trip", File.ReadAllText(Path.Combine(server.Root, "uploaded.txt")));
    }

    [Fact]
    public async Task Curl_can_download_list_and_upload()
    {
        if (ResolveCurl() is not { } curl)
        {
            Assert.Skip("curl is not available on this machine");
            return;
        }

        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("grab.txt", "curl payload");

        var baseUrl = $"ftp://127.0.0.1:{server.Port}/";
        const string auth = "anonymous:a@b.c";

        var download = await RunAsync(curl, $"-s -u {auth} {baseUrl}grab.txt");
        Assert.Equal(0, download.ExitCode);
        Assert.Equal("curl payload", download.StdOut);

        // --list-only issues NLST.
        var list = await RunAsync(curl, $"-s -u {auth} --list-only {baseUrl}");
        Assert.Equal(0, list.ExitCode);
        Assert.Contains("grab.txt", list.StdOut);

        // A plain directory fetch issues LIST, so this exercises the ls-style formatter.
        var longList = await RunAsync(curl, $"-s -u {auth} {baseUrl}");
        Assert.Equal(0, longList.ExitCode);
        Assert.Contains("grab.txt", longList.StdOut);

        var source = Path.Combine(server.Root, "..", "curl-upload.txt");
        await File.WriteAllTextAsync(source, "uploaded by curl");

        try
        {
            var upload = await RunAsync(curl, $"-s -u {auth} -T \"{Path.GetFullPath(source)}\" {baseUrl}");
            Assert.Equal(0, upload.ExitCode);
            Assert.Equal("uploaded by curl", File.ReadAllText(Path.Combine(server.Root, "curl-upload.txt")));
        }
        finally
        {
            File.Delete(source);
        }
    }

    [Fact]
    public async Task Curl_can_resume_a_partial_download()
    {
        if (ResolveCurl() is not { } curl)
        {
            Assert.Skip("curl is not available on this machine");
            return;
        }

        await using var server = await FtpServerFixture.StartAsync();
        server.WriteFile("resume.txt", "0123456789");

        // -C 4 makes curl issue REST 4 before RETR.
        var partial = Path.Combine(Path.GetTempPath(), "curl-resume-" + Guid.NewGuid().ToString("N")[..8]);
        await File.WriteAllTextAsync(partial, "0123");

        try
        {
            var result = await RunAsync(curl, $"-s -u anonymous:a@b.c -C 4 -o \"{partial}\" ftp://127.0.0.1:{server.Port}/resume.txt");

            Assert.Equal(0, result.ExitCode);
            Assert.Equal("0123456789", await File.ReadAllTextAsync(partial));
        }
        finally
        {
            File.Delete(partial);
        }
    }

    [Fact]
    public async Task Curl_can_use_explicit_ftps()
    {
        if (ResolveCurl() is not { } curl)
        {
            Assert.Skip("curl is not available on this machine");
            return;
        }

        await using var server = await FtpServerFixture.StartAsync(o => o.Ftps = true);
        server.WriteFile("secure.txt", "over tls");

        // --ssl-reqd forces AUTH TLS; -k accepts the self-signed certificate.
        var result = await RunAsync(curl, $"-s -k --ssl-reqd -u anonymous:a@b.c ftp://127.0.0.1:{server.Port}/secure.txt");

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("over tls", result.StdOut);
    }

    private static readonly Lazy<string?> CurlPath = new(ProbeCurl);

    private static string? ResolveCurl() => CurlPath.Value;

    /// <summary>
    /// Returns null when curl is genuinely unavailable, so the tests skip rather than failing
    /// with a Win32Exception from Process.Start.
    /// </summary>
    private static string? ProbeCurl()
    {
        var candidates = OperatingSystem.IsWindows()
            ? [@"C:\Windows\System32\curl.exe", "curl.exe"]
            : new[] { "/usr/bin/curl", "/bin/curl", "curl" };

        foreach (var candidate in candidates)
        {
            if (Path.IsPathRooted(candidate))
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                continue;
            }

            // Not a rooted path: confirm it can actually be launched before committing to it.
            try
            {
                using var probe = Process.Start(new ProcessStartInfo(candidate, "--version")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                });

                if (probe is null)
                {
                    continue;
                }

                probe.WaitForExit(5000);
                return candidate;
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                // Not on PATH.
            }
        }

        return null;
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(string fileName, string arguments)
    {
        // --max-time bounds curl itself so a wedged server surfaces as a failure, not a hang.
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(fileName, "--max-time 20 --connect-timeout 5 " + arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            },
        };

        process.Start();

        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
        }
        catch (TimeoutException)
        {
            // Leaving it running would hold the server's sockets open for the rest of the run.
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // Already gone.
            }

            throw;
        }

        return (process.ExitCode, (await stdout).ReplaceLineEndings("\n").TrimEnd('\n'), await stderr);
    }
}
