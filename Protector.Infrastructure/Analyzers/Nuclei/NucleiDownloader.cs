using System.IO.Compression;
using System.Runtime.InteropServices;

namespace Protector.Infrastructure.Analyzers.Nuclei;

/// <summary>
/// Downloads the Nuclei binary from GitHub releases if not already present.
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
        progress?.Invoke("Downloading Nuclei scanner...");

        var downloadUrl = GetDownloadUrl();
        using var http = new HttpClient();
        http.Timeout = TimeSpan.FromMinutes(3);

        var zipPath = Path.Combine(InstallDir, "nuclei.zip");
        var bytes = await http.GetByteArrayAsync(downloadUrl, ct);
        await File.WriteAllBytesAsync(zipPath, bytes, ct);

        progress?.Invoke("Extracting Nuclei...");
        ZipFile.ExtractToDirectory(zipPath, InstallDir, overwriteFiles: true);
        File.Delete(zipPath);

        // Make executable on Linux/macOS
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            System.Diagnostics.Process.Start("chmod", $"+x {BinaryPath}");

        progress?.Invoke($"Nuclei installed at {BinaryPath}");
    }

    private static string GetDownloadUrl()
    {
        // Latest stable release from GitHub
        const string baseUrl = "https://github.com/projectdiscovery/nuclei/releases/latest/download";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return $"{baseUrl}/nuclei_windows_amd64.zip";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? $"{baseUrl}/nuclei_macos_arm64.zip"
                : $"{baseUrl}/nuclei_macos_amd64.zip";

        return RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? $"{baseUrl}/nuclei_linux_arm64.zip"
            : $"{baseUrl}/nuclei_linux_amd64.zip";
    }
}
