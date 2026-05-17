using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Protector.Infrastructure.Analyzers.Feroxbuster;

public static class FeroxbusterDownloader
{
    private static readonly string InstallDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".vscan", "feroxbuster");

    public static string BinaryPath => Path.Combine(
        InstallDir,
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "feroxbuster.exe" : "feroxbuster");

    public static bool IsInstalled => File.Exists(BinaryPath);

    public static async Task EnsureInstalledAsync(
        Action<string>? progress = null,
        CancellationToken ct = default)
    {
        if (IsInstalled) { progress?.Invoke("feroxbuster found."); return; }

        Directory.CreateDirectory(InstallDir);
        using var http = new HttpClient();
        http.Timeout = TimeSpan.FromMinutes(5);
        http.DefaultRequestHeaders.Add("User-Agent", "V-Scan/1.0");

        progress?.Invoke("Fetching latest feroxbuster release...");
        var json = await http.GetStringAsync(
            "https://api.github.com/repos/epi052/feroxbuster/releases/latest", ct);

        var downloadUrl = ParseDownloadUrl(json);
        if (downloadUrl is null)
            throw new InvalidOperationException("Could not find feroxbuster download URL.");

        progress?.Invoke("Downloading feroxbuster...");
        var bytes = await http.GetByteArrayAsync(downloadUrl, ct);

        var zipPath = Path.Combine(InstallDir, "feroxbuster.zip");
        await File.WriteAllBytesAsync(zipPath, bytes, ct);

        progress?.Invoke("Extracting feroxbuster...");
        ZipFile.ExtractToDirectory(zipPath, InstallDir, overwriteFiles: true);
        File.Delete(zipPath);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            System.Diagnostics.Process.Start("chmod", $"+x {BinaryPath}");

        progress?.Invoke($"feroxbuster installed at {BinaryPath}");
    }

    private static string? ParseDownloadUrl(string json)
    {
        var assetName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "windows-x86_64.zip"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? "apple-darwin.tar.gz"
                : "linux-gnu.zip";

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
