using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Protector.Infrastructure.Analyzers.Httpx;

public static class HttpxDownloader
{
    private static readonly string InstallDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".vscan", "httpx");

    public static string BinaryPath => Path.Combine(
        InstallDir,
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "httpx.exe" : "httpx");

    public static bool IsInstalled => File.Exists(BinaryPath);

    public static async Task EnsureInstalledAsync(
        Action<string>? progress = null,
        CancellationToken ct = default)
    {
        if (IsInstalled)
        {
            progress?.Invoke("httpx binary found.");
            return;
        }

        Directory.CreateDirectory(InstallDir);

        using var http = new HttpClient();
        http.Timeout = TimeSpan.FromMinutes(5);
        http.DefaultRequestHeaders.Add("User-Agent", "V-Scan/1.0");

        progress?.Invoke("Fetching latest httpx release info...");
        var json = await http.GetStringAsync(
            "https://api.github.com/repos/projectdiscovery/httpx/releases/latest", ct);

        var downloadUrl = ParseDownloadUrl(json);
        if (downloadUrl is null)
            throw new InvalidOperationException("Could not find httpx download URL.");

        progress?.Invoke($"Downloading httpx...");
        var bytes = await http.GetByteArrayAsync(downloadUrl, ct);

        var zipPath = Path.Combine(InstallDir, "httpx.zip");
        await File.WriteAllBytesAsync(zipPath, bytes, ct);

        progress?.Invoke("Extracting httpx...");
        ZipFile.ExtractToDirectory(zipPath, InstallDir, overwriteFiles: true);
        File.Delete(zipPath);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            System.Diagnostics.Process.Start("chmod", $"+x {BinaryPath}");

        progress?.Invoke($"httpx installed at {BinaryPath}");
    }

    private static string? ParseDownloadUrl(string json)
    {
        var assetName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "windows_amd64.zip"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                    ? "macOS_arm64.zip" : "macOS_amd64.zip"
                : RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                    ? "linux_arm64.zip" : "linux_amd64.zip";

        using var doc = JsonDocument.Parse(json);
        foreach (var asset in doc.RootElement.GetProperty("assets").EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? "";
            if (name.Contains(assetName, StringComparison.OrdinalIgnoreCase))
                return asset.GetProperty("browser_download_url").GetString();
        }
        return null;
    }
}
