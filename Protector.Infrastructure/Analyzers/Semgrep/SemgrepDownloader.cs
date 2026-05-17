using System.Runtime.InteropServices;

namespace Protector.Infrastructure.Analyzers.Semgrep;

public static class SemgrepDownloader
{
    private static readonly string InstallDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".vscan", "semgrep");

    // semgrep is installed via pip, not as a single binary
    public static string BinaryPath => RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? FindInPath("semgrep.exe") ?? Path.Combine(InstallDir, "semgrep.exe")
        : FindInPath("semgrep") ?? "/usr/local/bin/semgrep";

    public static bool IsInstalled => FindInPath(
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "semgrep.exe" : "semgrep") is not null;

    public static async Task EnsureInstalledAsync(
        Action<string>? progress = null,
        CancellationToken ct = default)
    {
        if (IsInstalled) { progress?.Invoke("semgrep found."); return; }

        progress?.Invoke("Installing semgrep via pip...");
        progress?.Invoke("Requires Python 3.8+ and pip to be installed.");

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "pip",
            Arguments = "install semgrep",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("pip not found. Install Python first.");

        await process.WaitForExitAsync(ct);

        if (process.ExitCode != 0)
            throw new InvalidOperationException("semgrep installation failed. Run: pip install semgrep");

        progress?.Invoke("semgrep installed successfully.");
    }

    private static string? FindInPath(string binaryName)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            var fullPath = Path.Combine(dir, binaryName);
            if (File.Exists(fullPath)) return fullPath;
        }
        return null;
    }
}
