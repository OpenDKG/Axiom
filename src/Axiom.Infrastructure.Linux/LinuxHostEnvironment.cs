// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Linux;

/// <summary>
/// Facts about the Linux host that change what the product can honestly claim. They are reported
/// as limitations, never used to silently change behaviour or to claim an exercised environment.
/// </summary>
public sealed record LinuxHostEnvironment(
    bool IsWsl,
    bool IsContainer,
    IReadOnlyList<string> SecurityModules,
    string? AppArmorProfile,
    string? SelinuxEnforcement)
{
    public static LinuxHostEnvironment Detect() =>
        Detect(path =>
        {
            try
            {
                return File.Exists(path) ? File.ReadAllText(path) : null;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        });

    internal static LinuxHostEnvironment Detect(Func<string, string?> readFile)
    {
        ArgumentNullException.ThrowIfNull(readFile);

        var kernel = (TryRead(readFile, "/proc/sys/kernel/osrelease") ?? string.Empty) + " " +
                     (TryRead(readFile, "/proc/version") ?? string.Empty);
        var isWsl = kernel.Contains("microsoft", StringComparison.OrdinalIgnoreCase);
        var cgroup = TryRead(readFile, "/proc/self/cgroup") ?? string.Empty;
        var isContainer = readFile("/.dockerenv") is not null ||
                          readFile("/run/.containerenv") is not null ||
                          !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("container")) ||
                          cgroup.Contains("docker", StringComparison.OrdinalIgnoreCase) ||
                          cgroup.Contains("kubepods", StringComparison.OrdinalIgnoreCase);

        var lsm = (TryRead(readFile, "/sys/kernel/security/lsm") ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var current = TryRead(readFile, "/proc/self/attr/current") ?? string.Empty;
        var appArmor = current.Contains("(enforce)", StringComparison.OrdinalIgnoreCase) ||
                       current.Contains("(complain)", StringComparison.OrdinalIgnoreCase)
            ? current
            : null;

        var selinux = TryRead(readFile, "/sys/fs/selinux/enforce")?.Trim();

        return new LinuxHostEnvironment(
            isWsl,
            isContainer,
            lsm,
            appArmor,
            string.IsNullOrWhiteSpace(selinux) ? null : selinux);
    }

    public IReadOnlyList<string> Describe()
    {
        var notes = new List<string>();
        if (IsWsl)
        {
            notes.Add("Running under WSL: systemd, cgroup v2 and eBPF availability depend on the WSL " +
                      "version and .wslconfig; per-executable firewall enforcement is not claimed here.");
        }

        if (IsContainer)
        {
            notes.Add("Running inside a container: socket attribution is limited to this container's " +
                      "namespace, and firewall enforcement needs a delegated cgroup v2 hierarchy plus " +
                      "CAP_BPF/CAP_NET_ADMIN.");
        }

        if (SecurityModules.Count > 0)
        {
            notes.Add($"LSM(s) active: {string.Join(", ", SecurityModules)}. Confined host profiles can " +
                      "deny BPF, /proc access or socket creation; this build reports the restriction " +
                      "rather than bypassing it.");
        }

        if (AppArmorProfile is not null)
        {
            notes.Add($"AppArmor profile: {AppArmorProfile}");
        }

        if (SelinuxEnforcement is not null)
        {
            notes.Add(SelinuxEnforcement == "1"
                ? "SELinux is enforcing; unlabelled eBPF or /proc access may be denied."
                : "SELinux is permissive.");
        }

        return notes;
    }

    private static string? TryRead(Func<string, string?> readFile, string path) => readFile(path);
}
