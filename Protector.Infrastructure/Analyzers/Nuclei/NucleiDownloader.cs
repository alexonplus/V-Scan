using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Protector.Infrastructure.Analyzers.Nuclei;

/// <summary>
/// Downloads the Nuclei binary from GitHub releases if not already present.
/// Uses GitHub API to find the correct versioned filename first.
/// Stores it in ~/.vscan/nuclei/ so it persists between runs.
/// </summary>
public static class NucleiDownloader
{
    private static readonly string InstallDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".vscan", "nuclei");

    public static string BinaryPath => Path.Combine(
        InstallDir,
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "nuclei.exe" : "nuclei");

    public static bool IsInstalled => File.Exists(BinaryPath);

    public static async Task EnsureInstalledAsync(
        Action<string>? progress = null,
        CancellationToken ct = default)
    {
        if (IsInstalled)
        {
            progress?.Invoke("Nuclei binary found.");
            return;
        }

        Directory.CreateDirectory(InstallDir);

        using var http = new HttpClient();
        http.Timeout = TimeSpan.FromMinutes(5);
        http.DefaultRequestHeaders.Add("User-Agent", "V-Scan/1.0");

        // Step 1: ask GitHub API for the latest release info
        progress?.Invoke("Fetching latest Nuclei release info...");
        var apiUrl = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest";
        var json = await http.GetStringAsync(apiUrl, ct);

        var downloadUrl = ParseDownloadUrl(json);
        if (downloadUrl is null)
            throw new InvalidOperationException("Could not find Nuclei download URL in GitHub release.");

        progress?.Invoke($"Downloading Nuclei from {downloadUrl}...");

        var zipPath = Path.Combine(InstallDir, "nuclei.zip");
        var bytes = await http.GetByteArrayAsync(downloadUrl, ct);
        await File.WriteAllBytesAsync(zipPath, bytes, ct);

        progress?.Invoke("Extracting Nuclei...");
        ZipFile.ExtractToDirectory(zipPath, InstallDir, overwriteFiles: true);
        File.Delete(zipPath);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            System.Diagnostics.Process.Start("chmod", $"+x {BinaryPath}");

        progress?.Invoke($"Nuclei installed at {BinaryPath}");
    }

    private static string? ParseDownloadUrl(string json)
    {
        var assetName = GetAssetName();

        using var doc = JsonDocument.Parse(json);
        var assets = doc.RootElement.GetProperty("assets");

        foreach (var asset in assets.EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? "";
            if (name.Contains(assetName, StringComparison.OrdinalIgnoreCase))
                return asset.GetProperty("browser_download_url").GetString();
        }

        return null;
    }

    private static string GetAssetName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "windows_amd64.zip";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? "macOS_arm64.zip"
                : "macOS_amd64.zip";

        return RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? "linux_arm64.zip"
            : "linux_amd64.zip";
    }
}
