// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.Systemd;

/// <summary>
/// The <c>axiomd.service</c> unit (docs/LINUX_ARCHITECTURE.md §3). Written by
/// <c>axiomd --install-service</c>, removed by <c>--uninstall-service</c>; every hardening
/// directive carries the reason it is needed so a reviewer can tighten or relax it deliberately.
/// </summary>
public static class SystemdUnit
{
    public const string ServiceEnvironmentVariable = "AXIOM_SERVICE";

    public const int RestartDelaySeconds = 10;

    /// <summary>
    /// Capabilities the root daemon keeps (bounding set; everything else is dropped):
    /// CAP_NET_ADMIN (nftables, resolvectl), CAP_NET_RAW (raw/packet sockets for the future BPF
    /// helper), CAP_SYS_ADMIN (writing <c>cgroup.procs</c> of foreign cgroups, bpf()),
    /// CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH (reading <c>/proc/&lt;pid&gt;/fd</c>, <c>exe</c>,
    /// <c>cmdline</c> of every user's processes for socket attribution), CAP_DAC_OVERRIDE
    /// (<c>/etc/resolv.conf</c> fallback and NetworkManager/resolved state files),
    /// CAP_CHOWN + CAP_FOWNER (0700/0600 enforcement of <c>/var/lib/axiom</c>), CAP_KILL
    /// (ending a blocked process on request).
    /// </summary>
    public const string CapabilityBoundingSet =
        "CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_KILL";

    /// <summary>The unit text (pure; unit-tested).</summary>
    public static string Build(string executablePath, string machineDataDirectory, string runDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(machineDataDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(runDirectory);

        var workingDirectory = Path.GetDirectoryName(executablePath) ?? "/";
        return string.Create(
            CultureInfo.InvariantCulture,
            $"""
            # Axiom firewall daemon. Written by `axiomd --install-service`; removed by `axiomd --uninstall-service`.
            [Unit]
            Description=Axiom firewall daemon
            Documentation=https://github.com/a-51-50/Axiom/blob/main/docs/LINUX_ARCHITECTURE.md
            After=network-pre.target nss-lookup.target systemd-resolved.service NetworkManager.service
            Wants=network-pre.target

            [Service]
            # The daemon sends READY=1 over $NOTIFY_SOCKET once the IPC socket listens (SdNotify).
            Type=notify
            NotifyAccess=main
            ExecStart={Q(executablePath)}
            WorkingDirectory={Q(workingDirectory)}
            Environment={ServiceEnvironmentVariable}=1
            Environment=DOTNET_CLI_TELEMETRY_OPTOUT=1
            Environment=DOTNET_NOLOGO=1
            Restart=on-failure
            RestartSec={RestartDelaySeconds}
            # A clean exit (uninstall, explicit stop) must not be restarted; a crash must.
            SuccessExitStatus=0
            KillMode=mixed
            TimeoutStopSec=30

            # systemd creates and owns these directories with the modes below:
            #   /run/axiom      0755  IPC socket (0666, peer uid checked) and filter socket (0600)
            #   /var/lib/axiom  0700  database, rules, Privacy Shield backup, recovery baseline (root only)
            #   /var/log/axiom  0750  reserved for file logs; stdout/stderr go to the journal
            RuntimeDirectory=axiom
            RuntimeDirectoryMode=0755
            RuntimeDirectoryPreserve=no
            StateDirectory=axiom
            StateDirectoryMode=0700
            LogsDirectory=axiom
            LogsDirectoryMode=0750

            # Hardening. The daemon runs as root (it must program nftables, read every process's
            # /proc entries and rewrite system DNS) but with a reduced capability set and a read-only
            # view of the OS; only the state/run directories, the cgroup tree and the resolver
            # configuration are writable.
            ProtectSystem=strict
            ReadWritePaths={Q(machineDataDirectory)} {Q(runDirectory)} /sys/fs/cgroup /etc/resolv.conf /run/systemd/resolve /run/NetworkManager
            ProtectHome=read-only
            PrivateTmp=yes
            ProtectKernelTunables=yes
            ProtectKernelModules=yes
            ProtectControlGroups=no
            ProtectClock=yes
            RestrictSUIDSGID=yes
            RestrictRealtime=yes
            LockPersonality=yes
            # No setuid helpers are executed; nftables and resolvectl work with the bounding set alone.
            NoNewPrivileges=yes
            # See SystemdUnit.CapabilityBoundingSet for the reason behind every capability.
            CapabilityBoundingSet={CapabilityBoundingSet}
            RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
            SystemCallArchitectures=native

            [Install]
            WantedBy=multi-user.target

            """);
    }

    /// <summary>Quotes a path for a unit directive (systemd unquotes C-style escapes inside double quotes).</summary>
    private static string Q(string value) =>
        value.Any(character => char.IsWhiteSpace(character) || character is '"' or '\\')
            ? "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\""
            : value;

    /// <summary>Value of <c>ExecStart=</c> in a unit file (first unquoted token), or null.</summary>
    public static string? ReadExecStart(string unitText)
    {
        ArgumentNullException.ThrowIfNull(unitText);
        foreach (var raw in unitText.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("ExecStart=", StringComparison.Ordinal))
            {
                continue;
            }

            var value = line["ExecStart=".Length..].Trim();
            if (value.StartsWith('"'))
            {
                var end = value.IndexOf('"', 1);
                return end < 0 ? null : value[1..end].Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal);
            }

            return value.Split(' ', 2)[0];
        }

        return null;
    }
}
