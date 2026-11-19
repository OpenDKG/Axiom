// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Axiom.Contracts;
using Axiom.Contracts.Blackbox;
using Axiom.Contracts.Community;
using Axiom.Contracts.Files;
using Axiom.Contracts.Firewall;
using Axiom.Contracts.Modules;
using Axiom.Contracts.Reputation;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>One loopback probe sample for the activity strip.</summary>
public sealed record ModuleActivity(DateTimeOffset At, bool DkgConnected, bool BlackboxConnected);

/// <summary>One square in the module health strip; placeholders keep the 30-check window visible.</summary>
public sealed record ModuleHealthSlot(bool HasSample, bool DkgConnected, bool BlackboxConnected)
{
    public bool DkgOn => HasSample && DkgConnected;

    public bool DkgOff => HasSample && !DkgConnected;

    public bool BlackboxOn => HasSample && BlackboxConnected;

    public bool BlackboxOff => HasSample && !BlackboxConnected;

    public bool IsPlaceholder => !HasSample;
}

/// <summary>Status of one optional security or intelligence module.</summary>
public sealed record SecurityModule(
    string Name,
    string Status,
    string Detail,
    string Glyph,
    bool IsConnected = false,
    bool CanAct = false,
    string ActionLabel = "Install",
    bool CanUninstall = false,
    bool CanSetMode = false,
    bool CanRepair = false)
{
    public bool IsAgentModule => Name is "Blackbox" or "OriginTrail DKG";

    public bool IsSecurityModule => Name is "Reputation provider" or "Community feed" or "File scanning";

    public bool IsBlackbox => Name == "Blackbox";
}

public sealed partial class FileScanRow : ObservableObject
{
    public FileScanRow(FileScanEntry entry)
    {
        Path = entry.Path;
        Name = System.IO.Path.GetFileName(entry.Path);
        SizeBytes = entry.SizeBytes;
        Sha256 = entry.Sha256;
        SkippedReason = entry.SkippedReason;
        _verdictText = entry.Sha256 is null ? "Skipped" : "VT: Not checked";
    }

    public string Path { get; }

    public string Name { get; }

    public long SizeBytes { get; }

    public string? Sha256 { get; }

    public string? SkippedReason { get; }

    public bool HasHash => Sha256 is not null;

    public string SizeText => $"{SizeBytes:N0} B";

    public string HashText => Sha256 ?? SkippedReason ?? "—";

    public string StatusText => Sha256 is null ? "SKIPPED" : "HASHED";

    [ObservableProperty]
    private string _verdictText;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanBlockFromCommunity))]
    private bool _isCommunityMatch;

    [ObservableProperty]
    private string _communityText = string.Empty;

    public bool CanBlockFromCommunity =>
        IsCommunityMatch &&
        Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
}

public sealed record CommunityFeedRow(string Sha256, string Name, string Verdict, string Source);

/// <summary>One Hermes/OpenClaw workspace reported by the local Blackbox dashboard.</summary>
public sealed record ProtectedAgent(string Kind, string Target, string Status, string Detail)
{
    public string KindText => Kind.ToLowerInvariant() switch
    {
        "hermes" => "Hermes",
        "openclaw" => "OpenClaw",
        "opencode" => "OpenCode",
        "openchamber" => "OpenChamber",
        "codex" => "Codex",
        "claude" => "Claude Code",
        "antigravity" => "Antigravity",
        "cursor" => "Cursor",
        "copilot" => "GitHub Copilot CLI",
        "gemini" => "Gemini CLI",
        "windsurf" => "Windsurf Cascade",
        "cline" => "Cline",
        "zcode" => "ZCode",
        "deepseek" => "DeepSeek Harness",
        _ => Kind,
    };

    public string TargetText => string.IsNullOrWhiteSpace(Target) ? "No workspace detected" : Target;

    /// <summary>
    /// Human-readable state. A configured hook is "HOOKED" until runtime evidence proves that it
    /// reached the local guard; it then becomes "CONNECTED". Blackbox-attached Hermes/OpenClaw
    /// workspaces keep the stronger "PROTECTED" label.
    /// </summary>
    public string DisplayStatus => Status switch
    {
        "HOOK INSTALLED" => "HOOKED",
        "HOOK LOADED" => "CONNECTED",
        "VERIFIED BLOCKING" => "VERIFIED",
        _ => Status,
    };

    public bool IsProtected => Status == "PROTECTED";

    /// <summary>
    /// Traffic-light tone for the status badge. Green means the hook is loaded or verified,
    /// orange means it is installed but still needs trust or a test, red means the guard failed.
    /// </summary>
    public bool ToneOk => Status is "PROTECTED" or "VERIFIED BLOCKING" or "HOOK LOADED";

    public bool ToneWarn => Status is "HOOK INSTALLED" or "TRUST REQUIRED" or "DETECTED" or "AUDIT ONLY" or "TESTING";

    public bool ToneFail => Status is "DEGRADED" or "OFFLINE" or "FAIL";

    public bool ToneIdle => !ToneOk && !ToneWarn && !ToneFail;

    public string ToneHint => Status switch
    {
        "PROTECTED" or "VERIFIED BLOCKING" or "HOOK LOADED" => "Hooked and reachable; the guard answered the canary test.",
        "HOOK INSTALLED" => "Hook installed but not proven. Run Test hook; a passing test turns this green.",
        "TRUST REQUIRED" => "Installed but not trusted by the host yet. Trust it, then test.",
        "DETECTED" => "Agent detected without an Axiom hook. Install/repair hooks.",
        "AUDIT ONLY" => "The hook answered but nothing was blocked. Use block mode, then test again.",
        "DEGRADED" => "The hook reached the guard but the guard failed. Fail-open means no protection.",
        "OFFLINE" => "Blackbox is offline, so the hook cannot answer.",
        "TESTING" => "Hook test is running.",
        _ => "Not detected on this machine.",
    };

    public bool CanTest => Kind is "opencode" or "openchamber" or "codex" or "claude" or "cursor" or "copilot" or "gemini" or "windsurf" or "cline" or "zcode" or "deepseek";

    public string TestResult { get; init; } = string.Empty;

    public bool ProcessRunning { get; init; }

    public bool TrustRequired { get; init; }
}

/// <summary>
/// Security page. Optional modules are read-only status probes; install buttons launch the official
/// third-party installer only after an explicit warning. Axiom does not stop or control a module.
/// </summary>
public sealed partial class SecurityPageViewModel : PageViewModel, IDisposable
{
    private readonly OptionalModuleProbe _probe;

    private readonly OptionalModuleInstaller _installer = new();

    private readonly OptionalModuleUninstaller _uninstaller = new();

    private readonly BlackboxModeStore _blackboxMode = new();

    private readonly BoundedHistory<ModuleActivity> _activityHistory = new(30);

    private readonly ReputationSettingsStore _reputationStore;

    private readonly VirusTotalClient _virusTotal = new();

    private readonly CommunityFeedSettingsStore _communityStore;

    private readonly CommunityFeedClient _communityClient = new();

    private readonly HttpClient _blackboxClient = OptionalModuleProbe.CreateLoopbackHttpClient(TimeSpan.FromSeconds(4));

    private readonly OpenCodeProtection _openCodeProtection = new();

    private readonly CodexProtection _codexProtection = new();

    private readonly ClaudeProtection _claudeProtection = new();

    private readonly AntigravityProtection _antigravityProtection = new();

    private readonly CursorProtection _cursorProtection = new();

    private readonly CopilotProtection _copilotProtection = new();

    private readonly GeminiProtection _geminiProtection = new();

    private readonly WindsurfProtection _windsurfProtection = new();

    private readonly ClineProtection _clineProtection = new();

    private readonly ZCodeProtection _zCodeProtection = new();

    private readonly DeepSeekProtection _deepSeekProtection = new();

    private readonly AgentHookProbe _agentHookProbe = new();

    private readonly UserStateProtection _userStateProtection = new();

    private readonly AgentEvidenceStore _agentEvidence = new();

    private static readonly TimeSpan EvidenceLifetime = TimeSpan.FromMinutes(5);

    private readonly HashSet<string> _verifiedBlockingAgents = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Agents whose last manual hook test did not run or failed; kept red until a test passes.</summary>
    private readonly HashSet<string> _failedHookTests = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Agents whose test proved the hook reaches the guard; kept green as CONNECTED.</summary>
    private readonly HashSet<string> _loadedHookAgents = new(StringComparer.OrdinalIgnoreCase);

    private bool IsAuditOnly => string.Equals(BlackboxModeText, "audit", StringComparison.OrdinalIgnoreCase);

    private ReputationSettings _reputationSettings = new(false, string.Empty);

    private CommunityFeedSettings _communitySettings = new(false, string.Empty, string.Empty);

    private bool _communityConnected;
    private Task? _communityLoadTask;
    private readonly HashSet<string> _notifiedCommunityHashes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>How often a module that is installed but down is started again this session.</summary>
    private static readonly TimeSpan AutoStartRetryInterval = TimeSpan.FromMinutes(3);

    private const int MaxAutoStartAttempts = 5;

    private DateTimeOffset _lastDkgStartAttempt = DateTimeOffset.MinValue;
    private DateTimeOffset _lastBlackboxStartAttempt = DateTimeOffset.MinValue;
    private int _dkgStartAttempts;
    private int _blackboxStartAttempts;
    private const string StartingDkg = "Starting the installed DKG node...";
    private const string StartingBlackbox = "Starting the installed Blackbox dashboard...";
    private readonly CancellationTokenSource _lifetime = new();
    private readonly IUiTimer _moduleTimer;
    private bool _presentationVisible = true;
    private bool _disposed;
    private readonly IUserInteraction _ui;
    private readonly ISecurityDialogService _dialogs;
    private readonly IShellActions _shell;
    private readonly ConnectionActionService _actions;

    public SecurityPageViewModel(
        IUserInteraction ui,
        ISecurityDialogService dialogs,
        IApiKeyProtector protector,
        IUiTimerFactory timers,
        IShellActions shell,
        IServiceRequestClient? serviceClient = null,
        ILoopbackListenerInspector? listenerInspector = null)
        : base("Integrations", "Optional modules, API keys and integration health", "\uE8D7")
    {
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentNullException.ThrowIfNull(dialogs);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(timers);
        ArgumentNullException.ThrowIfNull(shell);
        _ui = ui;
        _dialogs = dialogs;
        _shell = shell;
        _actions = new ConnectionActionService(serviceClient, _ui, new UnsupportedProcessActions());
        _probe = new OptionalModuleProbe(listenerInspector: listenerInspector);
        _reputationStore = new ReputationSettingsStore(protector);
        _communityStore = new CommunityFeedSettingsStore(protector);

        _reputationSettings = _reputationStore.Load();
        _communitySettings = _communityStore.Load();
        _communityConnected = IsBundledStarterAvailable();
        _blackboxModeText = _blackboxMode.GetMode();
        Modules = [];
        SeedCheckingState();

        if (_communitySettings.Enabled && !string.IsNullOrWhiteSpace(_communitySettings.Url))
        {
            _ = RefreshCommunityAsync();
        }

        _moduleTimer = timers.Create(TimeSpan.FromSeconds(15));
        _moduleTimer.Tick += (_, _) => _ = RefreshCoreAsync(includeAgentDetails: _presentationVisible);
        if (!DistributionContext.IsStorePackage)
        {
            _moduleTimer.Start();
        }

        SyncModuleHealth();
        _ = RefreshAsync();
    }

    /// <summary>Fixed window of module health squares, oldest on the left.</summary>
    public const int ModuleHealthWindow = 30;

    public ObservableCollection<ModuleHealthSlot> ModuleHealthSlots { get; } = [];

    [ObservableProperty]
    private string _dkgBrandLabel = "OriginTrail DKG · checking";

    [ObservableProperty]
    private string _blackboxBrandLabel = "Umanitek Blackbox · checking";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DkgHealthLabel))]
    private bool _dkgConnected;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BlackboxHealthLabel))]
    private bool _blackboxConnected;

    [ObservableProperty]
    private string _moduleActivitySummary = "No health samples yet.";

    public string DkgHealthLabel => DkgConnected ? "CONNECTED" : "NOT CONNECTED";

    public string BlackboxHealthLabel => BlackboxConnected ? "CONNECTED" : "NOT CONNECTED";

    public ObservableCollection<SecurityModule> Modules { get; }

    public ObservableCollection<ModuleActivity> Activity { get; } = [];

    public ObservableCollection<FileScanRow> FileScanResults { get; } = [];

    public ObservableCollection<CommunityFeedRow> CommunityEntries { get; } = [];

    public ObservableCollection<ProtectedAgent> ProtectedAgents { get; } = [];

    public TraderShieldSectionViewModel TraderShield { get; } = new();

    public bool IsAgentProtectionAvailable => !DistributionContext.IsStorePackage;

    [ObservableProperty]
    private string _fileScanStatus = "No folder scanned.";

    [ObservableProperty]
    private bool _hasCommunityMatches;

    [ObservableProperty]
    private bool _hasScanCommunityNotice;

    [ObservableProperty]
    private string _communityMatchesText = "No community feed matches in the scanned files.";

    [ObservableProperty]
    private string _communityStatusText = "Not configured.";

    [ObservableProperty]
    private string _agentsStatusText = "Blackbox is not connected; no agent protection status is available.";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _isFetchingCommunity;

    [ObservableProperty]
    private bool _isCheckingHash;

    private string ReputationStatus => _reputationSettings.Enabled && !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)
        ? "CONFIGURED"
        : "NOT CONFIGURED";

    private string ReputationDetail => _reputationSettings.Enabled && !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey)
        ? "Hash-only lookups enabled; the API key is stored with Windows DPAPI."
        : "No external reputation lookup is enabled. Unknown is shown as unknown.";

    private bool IsCommunityConfigured =>
        _communitySettings.Enabled && !string.IsNullOrWhiteSpace(_communitySettings.Url);

    private bool IsStarterFeed =>
        string.Equals(_communitySettings.Url, CommunityFeedSettingsStore.StarterFeedUrl, StringComparison.OrdinalIgnoreCase);

    private bool IsBundledStarterAvailable() =>
        IsCommunityConfigured &&
        IsStarterFeed &&
        File.Exists(Path.Combine(AppContext.BaseDirectory, "community", "feed.json"));

    private string CommunityStatus => IsCommunityConfigured && _communityConnected
        ? "CONNECTED"
        : IsCommunityConfigured ? "CONFIGURED" : "NOT CONFIGURED";

    private string CommunityDetail => IsCommunityConfigured && _communityConnected
        ? IsStarterFeed
            ? "Bundled starter feed loaded; entries are evidence, not a verdict."
            : "HTTPS feed loaded; entries are evidence, not a verdict."
        : IsCommunityConfigured
            ? IsStarterFeed
                ? "Bundled starter feed configured; waiting for the first refresh."
                : "HTTPS feed configured; entries are evidence, not a verdict."
            : "No community report is fetched, verified or published.";

    [ObservableProperty]
    private bool _isBusy;

    /// <summary>One install/repair/start flow at a time, so module port checks stay meaningful.</summary>
    private bool _moduleActionRunning;

    [ObservableProperty]
    private string _lastCheckedText = "Not checked yet";

    [ObservableProperty]
    private string _installStatusText = string.Empty;

    [ObservableProperty]
    private string _blackboxModeText = "audit";

    /// <summary>Block is the only mode that refuses an action; the card shows it as the active one.</summary>
    public bool BlackboxModeIsBlock => !IsAuditOnly;

    public bool BlackboxModeIsAudit => IsAuditOnly;

    public string BlackboxModeExplanation => IsAuditOnly
        ? "Audit records every guarded action but blocks nothing. Switch to Block before you rely on agent protection."
        : "Block refuses proven prompt injection, tool escalation and protected credential/file reads. Local blocking works without the DKG node.";

    public string ModuleDependencyNote =>
        "Blackbox blocks locally on its own. The DKG node adds shared-graph evidence: indicators corroborated " +
        "by other nodes, and publishing your signed, redacted sightings. If DKG is down, local blocking keeps " +
        "working but the graph stays offline and new verified indicators are not received.";

    partial void OnBlackboxModeTextChanged(string value)
    {
        OnPropertyChanged(nameof(BlackboxModeIsBlock));
        OnPropertyChanged(nameof(BlackboxModeIsAudit));
        OnPropertyChanged(nameof(BlackboxModeExplanation));
    }

    public string StatusTitle
    {
        get
        {
            var connected = Modules.Count(module => module.IsConnected);
            return connected switch
            {
                0 => "Optional modules are off by design",
                1 => "1 optional module connected",
                _ => $"{connected} optional modules connected",
            };
        }
    }

    public string StatusBadge => Modules.Any(module => module.IsConnected) ? "CONNECTED" : "OFFLINE";

    public string StatusText => DistributionContext.IsStorePackage
        ? "Microsoft Store build: optional third-party modules and agent hooks are not included. Core local security features remain available."
        : Modules.Any(module => module.IsConnected)
            ? "Axiom reads loopback status. Install buttons open the official third-party installer only after confirmation."
            : "The standard build is local and offline. Use Install to open the official third-party installer after confirmation.";

    public string AgentStatusTitle
    {
        get
        {
            if (DistributionContext.IsStorePackage)
            {
                return "Agent protection is not included";
            }

            var connected = Modules.Count(module => module.IsAgentModule && module.IsConnected);
            return connected switch
            {
                0 => "No agents connected",
                1 => "1 agent connected",
                _ => $"{connected} agents connected",
            };
        }
    }

    public string AgentStatusBadge => DistributionContext.IsStorePackage
        ? "NOT INCLUDED"
        : Modules.Any(module => module.IsAgentModule && module.IsConnected)
            ? "CONNECTED"
            : "OFFLINE";

    public string AgentStatusText => DistributionContext.IsStorePackage
        ? "Microsoft Store build: optional DKG/Blackbox modules and agent hooks are excluded."
        : "DKG and Blackbox status, install actions and the workspaces they report. " +
          "OpenCode, OpenChamber, Codex, Claude Code, Cursor, GitHub Copilot CLI, Gemini CLI, Windsurf Cascade, Cline, ZCode, DeepSeek Harness and Hermes are listed below; an installed hook is not proof of runtime blocking.";

    public string AgentHookInstallHint => DistributionContext.IsStorePackage
        ? "Agent hook installation is not available in the Microsoft Store build."
        : "Status refresh is read-only. Axiom provisions Axiom-managed hooks for detected harnesses at startup; " +
          "Install/Repair hooks can force a repair. Partial installation leaves all agent hook files unchanged.";

    public string SecurityStatusTitle
    {
        get
        {
            var configured = Modules.Count(module => module.IsSecurityModule && module.IsConnected);
            return configured switch
            {
                0 => "Security modules are not configured",
                1 => "1 security module configured",
                _ => $"{configured} security modules configured",
            };
        }
    }

    public string SecurityStatusBadge => Modules.Any(module => module.IsSecurityModule && module.IsConnected)
        ? "CONFIGURED"
        : "OFFLINE";

    public string SecurityStatusText => DistributionContext.IsStorePackage
        ? "Reputation, community feed and local file scan. Agent protection is not included in the Microsoft Store build."
        : "Reputation, community feed and local file scan. Agent protection lives on the Agents page.";

    public void Dispose()
    {
        _disposed = true;
        _moduleTimer.StopTimer();
        _moduleTimer.Dispose();
        _lifetime.Cancel();
        _lifetime.Dispose();
        _probe.Dispose();
        _virusTotal.Dispose();
        _communityClient.Dispose();
        _blackboxClient.Dispose();
    }

    internal void SetPresentationVisible(bool visible)
    {
        if (_presentationVisible == visible || _disposed)
        {
            return;
        }

        _presentationVisible = visible;
        _moduleTimer.Interval = TimeSpan.FromSeconds(visible ? 15 : 60);
        if (visible)
        {
            _ = RefreshAsync();
        }
    }

    [RelayCommand]
    private Task RefreshAsync() => RefreshCoreAsync(includeAgentDetails: true);

    private async Task RefreshCoreAsync(bool includeAgentDetails)
    {
        if (IsBusy || _disposed)
        {
            return;
        }

        var cancellationToken = _lifetime.Token;
        IsBusy = true;

        try
        {
            if (DistributionContext.IsStorePackage)
            {
                Rebuild(
                    StoreModule("DKG is not included in the Microsoft Store build."),
                    StoreModule("Blackbox is not included in the Microsoft Store build."));
                ProtectedAgents.Clear();
                AgentsStatusText = AgentStatusText;
                LastCheckedText = $"Checked {DateTimeOffset.Now:HH:mm:ss}";
                Activity.Clear();
                return;
            }

            var dkgTask = _probe.ProbeDkgAsync(cancellationToken);
            var blackboxTask = _probe.ProbeBlackboxAsync(cancellationToken);

            await Task.WhenAll(dkgTask, blackboxTask).ConfigureAwait(true);

            cancellationToken.ThrowIfCancellationRequested();
            var dkg = dkgTask.Result;
            var blackbox = blackboxTask.Result;
            Rebuild(dkg, blackbox);
            if ((dkg.IsConnected && InstallStatusText == StartingDkg) ||
                (blackbox.IsConnected && InstallStatusText == StartingBlackbox))
            {
                InstallStatusText = string.Empty;
            }

            if (!_moduleActionRunning)
            {
                await TryStartInstalledDkgOnLaunchAsync(dkg).ConfigureAwait(true);
                cancellationToken.ThrowIfCancellationRequested();
            }

            if (!_moduleActionRunning)
            {
                await TryStartInstalledBlackboxOnLaunchAsync(blackbox).ConfigureAwait(true);
                cancellationToken.ThrowIfCancellationRequested();
            }

            LastCheckedText = $"Checked {DateTimeOffset.Now:HH:mm:ss}";
            if (includeAgentDetails)
            {
                await RefreshAgentsAsync(blackbox.IsConnected, cancellationToken).ConfigureAwait(true);
                ApplyHookTestStates();
            }

            AppendHealthSample(dkg.IsConnected, blackbox.IsConnected);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            IsBusy = false;
            if (!_disposed)
            {
                NotifyStatusProperties();
            }
        }
    }

    /// <summary>
    /// Starts an installed local DKG node once per session so the verified graph does not stay
    /// offline after Axiom restarts. A node that already answers is left untouched.
    /// </summary>
    private async Task TryStartInstalledDkgOnLaunchAsync(OptionalModuleStatus dkg)
    {
        if (dkg.IsConnected || DistributionContext.IsStorePackage || !_installer.IsDkgAvailable)
        {
            return;
        }

        if (_dkgStartAttempts >= MaxAutoStartAttempts ||
            DateTimeOffset.UtcNow - _lastDkgStartAttempt < AutoStartRetryInterval)
        {
            return;
        }

        _lastDkgStartAttempt = DateTimeOffset.UtcNow;
        _dkgStartAttempts++;
        if (await Task.Run(_installer.StartDkg).ConfigureAwait(true) && !_disposed && !_moduleActionRunning)
        {
            InstallStatusText = StartingDkg;
            DkgBrandLabel = "OriginTrail DKG – starting";
        }
    }

    /// <summary>
    /// Starts an installed local Blackbox dashboard silently once per retry window so agent graph
    /// status does not stay offline after a restart, a crash or a power loss. A dashboard that
    /// already answers, or a port that is still binding, is left untouched.
    /// </summary>
    private async Task TryStartInstalledBlackboxOnLaunchAsync(OptionalModuleStatus blackbox)
    {
        if (blackbox.IsConnected || DistributionContext.IsStorePackage ||
            !_uninstaller.IsBlackboxRuntimeInstalled)
        {
            return;
        }

        if (_blackboxStartAttempts >= MaxAutoStartAttempts ||
            DateTimeOffset.UtcNow - _lastBlackboxStartAttempt < AutoStartRetryInterval)
        {
            return;
        }

        _lastBlackboxStartAttempt = DateTimeOffset.UtcNow;
        _blackboxStartAttempts++;
        if (await Task.Run(_installer.StartBlackboxDashboard).ConfigureAwait(true) && !_disposed && !_moduleActionRunning)
        {
            InstallStatusText = StartingBlackbox;
            BlackboxBrandLabel = "Umanitek Blackbox – starting";
        }
    }

    private void AppendHealthSample(bool dkgConnected, bool blackboxConnected)
    {
        // Manual refreshes can arrive between timer ticks without adding a second nearby sample.
        if (_activityHistory.Count > 0 &&
            DateTimeOffset.Now - _activityHistory.Items[^1].At < TimeSpan.FromSeconds(3))
        {
            return;
        }

        _activityHistory.Add(new ModuleActivity(DateTimeOffset.Now, dkgConnected, blackboxConnected));
        SyncModuleHealth();
    }

    private void SyncModuleHealth()
    {
        Activity.Clear();
        foreach (var sample in _activityHistory.Items)
        {
            Activity.Add(sample);
        }

        ModuleHealthSlots.Clear();
        foreach (var sample in _activityHistory.Items)
        {
            ModuleHealthSlots.Add(new ModuleHealthSlot(true, sample.DkgConnected, sample.BlackboxConnected));
        }

        for (var index = _activityHistory.Count; index < ModuleHealthWindow; index++)
        {
            ModuleHealthSlots.Add(new ModuleHealthSlot(false, false, false));
        }

        ModuleActivitySummary = Activity.Count == 0
            ? $"0/{ModuleHealthWindow} checks · waiting for the first probe"
            : $"{Activity.Count}/{ModuleHealthWindow} checks · DKG up {Activity.Count(sample => sample.DkgConnected)} · " +
              $"Blackbox up {Activity.Count(sample => sample.BlackboxConnected)} · " +
              $"last {Activity[^1].At.ToLocalTime():HH:mm:ss}";
    }

    private void ApplyBrandLabels(bool dkgConnected, bool blackboxConnected)
    {
        DkgConnected = dkgConnected;
        BlackboxConnected = blackboxConnected;
        DkgBrandLabel = dkgConnected
            ? "Powered by OriginTrail · DKG connected"
            : "OriginTrail DKG · not connected";
        BlackboxBrandLabel = blackboxConnected
            ? "Blackbox by Umanitek · dashboard connected"
            : "Umanitek Blackbox · not connected";
    }

    private void SetModuleActionLabel(string moduleName, string label)
    {
        for (var index = 0; index < Modules.Count; index++)
        {
            if (Modules[index].Name == moduleName)
            {
                Modules[index] = Modules[index] with { ActionLabel = label };
                return;
            }
        }
    }

    private async Task<bool> WaitForModuleStartAsync(string moduleName, int attempts = 12)
    {
        var token = _disposed ? CancellationToken.None : _lifetime.Token;
        for (var attempt = 0; attempt < attempts && !_disposed; attempt++)
        {
            try
            {
                await Task.Delay(2000, token).ConfigureAwait(true);
            }
            catch (OperationCanceledException)
            {
                return false;
            }

            if (_disposed)
            {
                return false;
            }

            await RefreshAsync().ConfigureAwait(true);

            var module = Modules.FirstOrDefault(item => item.Name == moduleName);
            if (module?.IsConnected == true)
            {
                return true;
            }

            // RefreshAsync rebuilds the module list, so keep the visible action label honest
            // while the external process is still starting.
            SetModuleActionLabel(moduleName, "Starting...");
        }

        SetModuleActionLabel(moduleName, "Start");
        return false;
    }

    private async Task<bool> EnsureModulePrerequisitesAsync(bool includeVcRedist)
    {
        var report = ModulePrerequisites.Probe();
        var missingVc = includeVcRedist && !OptionalModuleInstaller.HasVcRuntime();
        if (report.IsSatisfied && !missingVc)
        {
            return true;
        }

        var missingParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(report.MissingSummary))
        {
            missingParts.Add(report.MissingSummary);
        }

        if (missingVc)
        {
            missingParts.Add("Visual C++ 2015-2022 Redistributable");
        }

        var summary = string.Join(", ", missingParts);
        InstallStatusText = $"Missing prerequisites: {summary}.";

        var rejectedPython = report.RejectedPythonVersions.Count == 0
            ? string.Empty
            : $"\n\nFound Python {string.Join(", ", report.RejectedPythonVersions)}, but Blackbox supports 3.11-3.13 only. " +
              "Axiom installs Python 3.12 and puts it first on the installer PATH.";

        var installNow = await _ui.ConfirmAsync(
            "Install prerequisites",
            $"The optional module installers need: {summary}.{rejectedPython}\n\n" +
            "Install them now? A PowerShell window shows every winget command.",
            "Install prerequisites",
            destructive: false,
            CancellationToken.None).ConfigureAwait(true);
        if (!installNow)
        {
            InstallStatusText = $"Install {summary} manually, then click Check again.";
            return false;
        }

        _installer.InstallPrerequisites(report, missingVc);
        InstallStatusText = _installer.LastError
            ?? $"Prerequisite installer opened in PowerShell for {summary}. Complete it, then click Check again.";
        return false;
    }

    [RelayCommand]
    private async Task ActOnModuleAsync(string? module)
    {
        if (string.IsNullOrWhiteSpace(module))
        {
            return;
        }

        if (DistributionContext.IsStorePackage &&
            (module.Equals("Blackbox", StringComparison.Ordinal) ||
             module.StartsWith("OriginTrail", StringComparison.Ordinal)))
        {
            InstallStatusText = "This optional third-party module is not included in the Microsoft Store build.";
            return;
        }

        if (module.Equals("File scanning", StringComparison.Ordinal))
        {
            await ScanFilesAsync().ConfigureAwait(true);
            return;
        }

        if (module.Equals("Reputation provider", StringComparison.Ordinal))
        {
            await SetupReputationAsync().ConfigureAwait(true);
            return;
        }

        if (module.Equals("Community feed", StringComparison.Ordinal))
        {
            await SetupCommunityAsync().ConfigureAwait(true);
            return;
        }

        if (_moduleActionRunning)
        {
            return;
        }

        _moduleActionRunning = true;
        try
        {
            await StartOrInstallModuleAsync(module).ConfigureAwait(true);
        }
        finally
        {
            _moduleActionRunning = false;
        }
    }

    private async Task StartOrInstallModuleAsync(string module)
    {
        if (module.Equals("Blackbox", StringComparison.Ordinal))
        {
            if (_uninstaller.IsBlackboxRuntimeInstalled)
            {
                SetModuleActionLabel(module, "Starting...");
                InstallStatusText = "Starting the Blackbox dashboard...";
                var started = await Task.Run(_installer.StartBlackboxDashboard).ConfigureAwait(true);
                if (!started)
                {
                    SetModuleActionLabel(module, _uninstaller.HasBlackboxFiles ? "Repair" : "Install");
                    InstallStatusText = "Blackbox venv is missing. Click Repair to reinstall it.";
                    return;
                }

                InstallStatusText = "Waiting for the Blackbox dashboard to answer...";
                if (!await WaitForModuleStartAsync(module).ConfigureAwait(true))
                {
                    InstallStatusText = "Blackbox did not answer after 24 seconds. Check its local log or start it manually.";
                }

                return;
            }

            if (!await EnsureModulePrerequisitesAsync(includeVcRedist: true).ConfigureAwait(true))
            {
                return;
            }

            var isRepair = _uninstaller.HasBlackboxFiles;
            var confirmed = await _ui.ConfirmAsync(
                isRepair ? "Repair Blackbox" : "Install Blackbox",
                "This downloads and runs Umanitek's official Windows installer with the Oxigraph/auto " +
                "backend (no Docker).\n\nIt installs Python packages, clones the repository and may " +
                "register a scheduled task. Review the installer; continue only if you trust it.",
                isRepair ? "Repair" : "Open installer",
                destructive: true,
                CancellationToken.None).ConfigureAwait(true);

            if (!confirmed)
            {
                return;
            }

            _installer.InstallBlackbox();
            if (_installer.LastError is { } blackboxError)
            {
                SetModuleActionLabel(module, isRepair ? "Repair" : "Install");
                InstallStatusText = blackboxError;
                return;
            }

            InstallStatusText = "Blackbox installer opened in PowerShell. Complete it, then click Check again.";
            return;
        }

        if (module.StartsWith("OriginTrail", StringComparison.Ordinal))
        {
            if (_installer.IsDkgAvailable)
            {
                SetModuleActionLabel(module, "Starting...");
                InstallStatusText = "Starting the DKG node...";
                var started = await Task.Run(_installer.StartDkg).ConfigureAwait(true);
                if (!started)
                {
                    SetModuleActionLabel(module, _uninstaller.HasDkgFiles ? "Repair" : "Install");
                    InstallStatusText = "DKG CLI is missing. Click Repair to reinstall it.";
                    return;
                }

                InstallStatusText = "Waiting for the DKG node to become ready...";
                if (!await WaitForModuleStartAsync(module, attempts: 45).ConfigureAwait(true))
                {
                    InstallStatusText = "DKG did not answer after 90 seconds. Check its local log or start it manually.";
                }

                return;
            }

            if (!await EnsureModulePrerequisitesAsync(includeVcRedist: false).ConfigureAwait(true))
            {
                return;
            }

            var isRepair = _uninstaller.HasDkgFiles;
            var confirmed = await _ui.ConfirmAsync(
                isRepair ? "Repair OriginTrail DKG" : "Install OriginTrail DKG",
                "This installs @origintrail-official/dkg into %LOCALAPPDATA%\\Axiom\\modules, " +
                "configures testnet and starts the node.\n\nIt needs Node.js/npm. Continue?",
                isRepair ? "Repair" : "Open installer",
                destructive: true,
                CancellationToken.None).ConfigureAwait(true);

            if (!confirmed)
            {
                return;
            }

            _installer.InstallDkg();
            if (_installer.LastError is { } dkgError)
            {
                SetModuleActionLabel(module, isRepair ? "Repair" : "Install");
                InstallStatusText = dkgError;
                return;
            }

            InstallStatusText = "DKG installer opened in PowerShell. Complete it, then click Check again.";
        }
    }

    /// <summary>
    /// Repairs an installed local service without reinstalling it: one clean runtime, one port.
    /// A module that has no runtime yet falls through to the normal Install/Repair path.
    /// </summary>
    [RelayCommand]
    private async Task RepairModuleAsync(string? module)
    {
        if (string.IsNullOrWhiteSpace(module) || _moduleActionRunning ||
            module is not ("Blackbox" or "OriginTrail DKG"))
        {
            return;
        }

        if (DistributionContext.IsStorePackage)
        {
            InstallStatusText = "This optional third-party module is not included in the Microsoft Store build.";
            return;
        }

        var isBlackbox = module.Equals("Blackbox", StringComparison.Ordinal);
        var installed = isBlackbox
            ? _uninstaller.IsBlackboxRuntimeInstalled
            : _installer.IsDkgAvailable;
        if (!installed)
        {
            await ActOnModuleAsync(module).ConfigureAwait(true);
            return;
        }

        _moduleActionRunning = true;
        try
        {
            SetModuleActionLabel(module, "Repairing...");
            InstallStatusText = $"Repairing {module}: stopping a stale runtime and starting one copy...";

            var restart = isBlackbox ? !BlackboxConnected : !DkgConnected;
            var ok = await Task.Run(
                () => _installer.RepairLocalModules(
                    blackbox: isBlackbox,
                    dkg: !isBlackbox,
                    restartBlackbox: isBlackbox && restart,
                    restartDkg: !isBlackbox && restart),
                CancellationToken.None).ConfigureAwait(true);

            var token = _disposed ? CancellationToken.None : _lifetime.Token;
            if (isBlackbox)
            {
                await LocalModuleRuntime
                    .WaitForPortAsync(LocalModuleRuntime.BlackboxPort, TimeSpan.FromSeconds(60), token)
                    .ConfigureAwait(true);
            }
            else
            {
                var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(120);
                while (DateTimeOffset.UtcNow < deadline && !LocalModuleRuntime.AnyDkgPortListening && !_disposed)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(true);
                }
            }

            if (_disposed)
            {
                return;
            }

            await RefreshAsync().ConfigureAwait(true);
            var state = Modules.FirstOrDefault(item => item.Name == module);
            InstallStatusText = state?.IsConnected == true
                ? $"{module} repaired and connected{(ok ? string.Empty : "; review the local log")}."
                : _installer.LastError
                  ?? $"{module} did not answer after the repair. Check its local log, then try Repair again.";
        }
        catch (OperationCanceledException) when (_disposed)
        {
        }
        finally
        {
            _moduleActionRunning = false;
            if (!_disposed)
            {
                await RefreshAsync().ConfigureAwait(true);
            }
        }
    }

    /// <summary>
    /// Starts both local modules in dependency order. Blackbox can block on its own; DKG adds the
    /// shared verified graph, so it is started first and its failure does not stop Blackbox.
    /// </summary>
    [RelayCommand]
    private async Task StartAllModulesAsync()
    {
        if (DistributionContext.IsStorePackage || _moduleActionRunning)
        {
            return;
        }

        _moduleActionRunning = true;
        try
        {
            SetModuleActionLabel("OriginTrail DKG", "Starting...");
            SetModuleActionLabel("Blackbox", "Starting...");
            InstallStatusText = "Starting local modules: the DKG node first, then the Blackbox dashboard.";

            var token = _disposed ? CancellationToken.None : _lifetime.Token;
            var dkgUp = DkgConnected || LocalModuleRuntime.AnyDkgPortListening;
            if (!dkgUp && _installer.IsDkgAvailable)
            {
                await Task.Run(_installer.StartDkg).ConfigureAwait(true);
                var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(90);
                while (DateTimeOffset.UtcNow < deadline && !LocalModuleRuntime.AnyDkgPortListening && !_disposed)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(true);
                }

                dkgUp = LocalModuleRuntime.AnyDkgPortListening;
            }

            var blackboxUp = BlackboxConnected || LocalModuleRuntime.IsPortListening(LocalModuleRuntime.BlackboxPort);
            if (!blackboxUp && _uninstaller.IsBlackboxRuntimeInstalled && !_disposed)
            {
                await Task.Run(_installer.StartBlackboxDashboard).ConfigureAwait(true);
                blackboxUp = await LocalModuleRuntime
                    .WaitForPortAsync(LocalModuleRuntime.BlackboxPort, TimeSpan.FromSeconds(60), token)
                    .ConfigureAwait(true);
            }

            if (_disposed)
            {
                return;
            }

            await RefreshAsync().ConfigureAwait(true);
            InstallStatusText = (dkgUp, blackboxUp) switch
            {
                (true, true) => "Local modules are up: DKG node and Blackbox dashboard connected.",
                (false, true) => "Blackbox is up. DKG is still offline, so local blocking works but shared-graph evidence is unavailable.",
                (true, false) => "DKG is up. Blackbox is still offline, so agent protection is not enforcing; use Repair on its card.",
                _ => "Neither local module answered. Install or Repair each card, then try Start local modules again.",
            };
        }
        catch (OperationCanceledException) when (_disposed)
        {
        }
        finally
        {
            _moduleActionRunning = false;
            if (!_disposed)
            {
                await RefreshAsync().ConfigureAwait(true);
            }
        }
    }

    [RelayCommand]
    private async Task CopyAgentDetailsAsync(ProtectedAgent? agent)
    {
        if (agent is null)
        {
            return;
        }

        var text = string.Join(
            Environment.NewLine,
            $"Agent: {agent.KindText}",
            $"Workspace: {agent.TargetText}",
            $"Status: {agent.DisplayStatus}",
            $"Process running: {(agent.ProcessRunning ? "yes" : "no")}",
            $"Trust required: {(agent.TrustRequired ? "yes" : "no")}",
            $"Detail: {agent.Detail}",
            $"Test: {agent.TestResult}");
        try
        {
            await _ui.CopyTextAsync(text, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
            InstallStatusText = "Clipboard is unavailable.";
        }
    }

    [RelayCommand]
    private async Task TestAgentAsync(ProtectedAgent? agent)
    {
        if (agent is null || !agent.CanTest)
        {
            return;
        }

        var index = ProtectedAgents.IndexOf(agent);
        if (index < 0)
        {
            return;
        }

        ProtectedAgents[index] = agent with { TestResult = "Testing hook adapter…", Status = "TESTING" };
        var result = await _agentHookProbe.TestAsync(agent.Kind, CancellationToken.None).ConfigureAwait(true);
        index = ProtectedAgents.IndexOf(ProtectedAgents.FirstOrDefault(item =>
            item.Kind == agent.Kind && item.Target == agent.Target) ?? agent);

        var blocked = string.Equals(result.Status, "BLOCKED", StringComparison.OrdinalIgnoreCase);
        var reachedGuard = !blocked &&
                           (result.Status.Contains("HOOK RAN", StringComparison.OrdinalIgnoreCase) ||
                            result.Status.Contains("ALLOWED", StringComparison.OrdinalIgnoreCase));

        if (blocked)
        {
            _verifiedBlockingAgents.Add(agent.Kind);
            _loadedHookAgents.Remove(agent.Kind);
            _failedHookTests.Remove(agent.Kind);
        }
        else if (reachedGuard)
        {
            _verifiedBlockingAgents.Remove(agent.Kind);
            _loadedHookAgents.Add(agent.Kind);
            _failedHookTests.Remove(agent.Kind);
        }
        else
        {
            _verifiedBlockingAgents.Remove(agent.Kind);
            _loadedHookAgents.Remove(agent.Kind);
            _failedHookTests.Add(agent.Kind);
        }

        if (index >= 0)
        {
            ProtectedAgents[index] = ProtectedAgents[index] with
            {
                TestResult = $"{result.Status}: {result.Detail}",
                Status = blocked ? "VERIFIED BLOCKING" : reachedGuard ? "HOOK LOADED" : "DEGRADED",
            };
        }

        AgentsStatusText = blocked
            ? $"{agent.KindText}: test blocked the canary call; marked verified."
            : reachedGuard
                ? $"{agent.KindText}: hook reached the guard; marked connected."
                : $"{agent.KindText}: test did not run or failed; marked degraded.";
    }

    /// <summary>
    /// Re-applies manual test outcomes after a status refresh so a passed test stays green and a
    /// failed one stays red instead of silently reverting to the file-presence state.
    /// </summary>
    private void ApplyHookTestStates()
    {
        for (var index = 0; index < ProtectedAgents.Count; index++)
        {
            var agent = ProtectedAgents[index];

            if (_failedHookTests.Contains(agent.Kind))
            {
                if (agent.Status is not "DEGRADED")
                {
                    ProtectedAgents[index] = agent with
                    {
                        Status = "DEGRADED",
                        Detail = "The last hook test did not run or failed. Fail-open means protection is not proven; run Test hook again after fixing the guard.",
                    };
                }

                continue;
            }

            if (_loadedHookAgents.Contains(agent.Kind))
            {
                if (agent.Status is not ("HOOK LOADED" or "VERIFIED BLOCKING"))
                {
                    ProtectedAgents[index] = agent with
                    {
                        Status = "HOOK LOADED",
                        Detail = "Hook test passed: the hook ran and the local guard answered. Blocking still depends on the guard policy.",
                    };
                }

                continue;
            }

            if (_verifiedBlockingAgents.Contains(agent.Kind) &&
                agent.Status is not ("VERIFIED BLOCKING" or "PROTECTED"))
            {
                ProtectedAgents[index] = agent with { Status = "VERIFIED BLOCKING" };
            }
        }
    }

    private void ApplyCommunityMatches()
    {
        var byHash = new Dictionary<string, CommunityFeedRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in CommunityEntries)
        {
            byHash[entry.Sha256] = entry;
        }

        var matches = 0;
        var matchedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var newlyMatched = new List<FileScanRow>();
        foreach (var row in FileScanResults)
        {
            if (row.Sha256 is { Length: 64 } hash && byHash.TryGetValue(hash, out var entry))
            {
                var verdict = string.IsNullOrWhiteSpace(entry.Verdict) || entry.Verdict == "—"
                    ? "listed"
                    : entry.Verdict;
                var source = string.IsNullOrWhiteSpace(entry.Source) || entry.Source == "—"
                    ? "community feed"
                    : entry.Source;
                row.CommunityText = $"COMMUNITY MATCH: {verdict} · {source}";
                row.IsCommunityMatch = true;
                matches++;
                matchedHashes.Add(hash);
                if (_notifiedCommunityHashes.Add(hash))
                {
                    newlyMatched.Add(row);
                }
            }
            else
            {
                row.CommunityText = string.Empty;
                row.IsCommunityMatch = false;
            }
        }

        _notifiedCommunityHashes.IntersectWith(matchedHashes);

        var hashedCount = FileScanResults.Count(row => row.HasHash);
        if (FileScanResults.Count == 0)
        {
            HasCommunityMatches = false;
            HasScanCommunityNotice = false;
            CommunityMatchesText = "No community feed matches in the scanned files.";
        }
        else if (matches > 0)
        {
            HasCommunityMatches = true;
            HasScanCommunityNotice = false;
            CommunityMatchesText =
                $"{matches} of {hashedCount} hashed file(s) match the community feed ({CommunityEntries.Count} hashes loaded). " +
                "Review before running; blocking is optional and never automatic.";
            FileScanStatus =
                $"{FileScanResults.Count} file(s) scanned · {matches} match(es) in {CommunityEntries.Count} community hashes. Hashes are not uploaded.";
        }
        else if (CommunityEntries.Count > 0)
        {
            HasCommunityMatches = false;
            HasScanCommunityNotice = true;
            CommunityMatchesText =
                $"Checked {hashedCount} hashed file(s) locally against {CommunityEntries.Count} community feed hashes: 0 matches. " +
                "Use VT Check on a row only if you want an online VirusTotal lookup (API key required).";
            FileScanStatus =
                $"{FileScanResults.Count} file(s) scanned · 0 matches in {CommunityEntries.Count} community hashes. Hashes are not uploaded.";
        }
        else if (IsCommunityConfigured)
        {
            HasCommunityMatches = false;
            HasScanCommunityNotice = true;
            CommunityMatchesText =
                "Community feed is enabled, but 0 hashes are loaded. Click Refresh feed below to download hashes and re-check these files.";
            FileScanStatus =
                $"{FileScanResults.Count} file(s) scanned locally · community feed not loaded. Hashes are not uploaded.";
        }
        else
        {
            HasCommunityMatches = false;
            HasScanCommunityNotice = true;
            CommunityMatchesText =
                "Community feed is off, so files were only hashed locally (0 lookups). " +
                "Enable Community feed (no API key needed) or click VT Check with a VirusTotal API key.";
            FileScanStatus =
                $"{FileScanResults.Count} file(s) scanned locally · community feed off. Hashes are not uploaded.";
        }

        if (newlyMatched.Count > 0)
        {
            var names = string.Join(", ", newlyMatched.Take(3).Select(row => row.Name));
            var suffix = newlyMatched.Count > 3 ? $" (+{newlyMatched.Count - 3} more)" : string.Empty;
            AxiomAlertService.Show(
                "Community feed alert",
                $"{newlyMatched.Count} scanned file(s) match the community feed: {names}{suffix}. " +
                "Open Security to review; blocking is optional.",
                page: typeof(SecurityPageViewModel));
        }
    }

    [RelayCommand]
    private async Task BlockCommunityMatchAsync(FileScanRow? row)
    {
        if (row is null || !row.CanBlockFromCommunity)
        {
            return;
        }

        FileScanStatus = await _actions
            .BlockAsync(row.Name, row.Path, FirewallDirection.Outbound)
            .ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task CheckHashAsync(FileScanRow? row)
    {
        if (row?.Sha256 is null)
        {
            return;
        }

        if (!_reputationSettings.Enabled || string.IsNullOrWhiteSpace(_reputationSettings.ApiKey))
        {
            await SetupReputationAsync().ConfigureAwait(true);
            if (!_reputationSettings.Enabled || string.IsNullOrWhiteSpace(_reputationSettings.ApiKey))
            {
                return;
            }
        }

        IsCheckingHash = true;
        row.VerdictText = "VT: Checking…";

        try
        {
            var report = await _virusTotal
                .LookupHashAsync(row.Sha256, _reputationSettings.ApiKey, CancellationToken.None)
                .ConfigureAwait(true);

            row.VerdictText = report.Summary;
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or TaskCanceledException or System.Text.Json.JsonException)
        {
            row.VerdictText = $"Lookup failed: {exception.Message}";
        }
        finally
        {
            IsCheckingHash = false;
        }
    }

    private async Task SetupReputationAsync()
    {
        var settings = await _dialogs
            .EditReputationAsync(_reputationSettings, CancellationToken.None)
            .ConfigureAwait(true);
        if (settings is null)
        {
            return;
        }

        _reputationSettings = settings;
        try
        {
            _reputationStore.Save(_reputationSettings);
        }
        catch (NotSupportedException)
        {
            InstallStatusText = "This host cannot protect the API key at rest; settings were not saved.";
            return;
        }

        await RefreshAsync().ConfigureAwait(true);
    }

    private async Task SetupCommunityAsync()
    {
        var settings = await _dialogs
            .EditCommunityAsync(_communitySettings, CancellationToken.None)
            .ConfigureAwait(true);
        if (settings is null)
        {
            return;
        }

        _communitySettings = settings;
        _communityConnected = false;
        try
        {
            _communityStore.Save(_communitySettings);
        }
        catch (NotSupportedException)
        {
            InstallStatusText = "This host cannot protect the feed token at rest; settings were not saved.";
            return;
        }

        await RefreshCommunityAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private Task RefreshCommunityAsync()
    {
        if (_communityLoadTask is { IsCompleted: false } inFlight)
        {
            return inFlight;
        }

        _communityLoadTask = LoadCommunityAsync(updateEntries: true);
        return _communityLoadTask;
    }

    [RelayCommand]
    private Task TestCommunityAsync() => LoadCommunityAsync(updateEntries: false);

    private async Task LoadCommunityAsync(bool updateEntries)
    {
        if (!IsCommunityConfigured)
        {
            _communityConnected = false;
            ReplaceCommunityModule();
            CommunityStatusText = "Not configured.";
            return;
        }

        IsFetchingCommunity = true;
        CommunityStatusText = updateEntries ? "Fetching feed…" : "Testing feed…";

        try
        {
            var result = await _communityClient
                .FetchAsync(_communitySettings.Url, _communitySettings.Token, CancellationToken.None)
                .ConfigureAwait(true);

            if (updateEntries)
            {
                CommunityEntries.Clear();
                foreach (var entry in result.Entries)
                {
                    CommunityEntries.Add(new CommunityFeedRow(
                        entry.Sha256,
                        entry.Name ?? "—",
                        entry.Verdict ?? "—",
                        entry.Source ?? "—"));
                }
            }

            ApplyCommunityMatches();

            _communityConnected = true;
            ReplaceCommunityModule();
            CommunityStatusText = updateEntries
                ? $"{result.Entries.Count} entries fetched at {result.FetchedUtc:HH:mm:ss}."
                : $"Feed test passed: {result.Entries.Count} entries at {result.FetchedUtc:HH:mm:ss}.";
        }
        catch (Exception exception) when (exception is
            HttpRequestException or InvalidDataException or System.Text.Json.JsonException or
            TaskCanceledException or ArgumentException or FileNotFoundException)
        {
            _communityConnected = false;
            ReplaceCommunityModule();
            CommunityStatusText = updateEntries
                ? $"Feed failed: {exception.Message}"
                : $"Feed test failed: {exception.Message}";
        }
        finally
        {
            IsFetchingCommunity = false;
        }
    }

    [RelayCommand]
    private async Task ScanFilesAsync()
    {
        var folder = await _ui
            .PickFolderAsync("Select a folder to hash locally", CancellationToken.None)
            .ConfigureAwait(true);
        if (folder is null)
        {
            return;
        }

        IsScanning = true;
        FileScanStatus = "Scanning selected folder…";
        FileScanResults.Clear();

        try
        {
            if (IsCommunityConfigured && CommunityEntries.Count == 0)
            {
                if (_communityLoadTask is { IsCompleted: false } inFlight)
                {
                    await inFlight.ConfigureAwait(true);
                }
                else if (!IsFetchingCommunity)
                {
                    await RefreshCommunityAsync().ConfigureAwait(true);
                }
            }

            var entries = await FileScanner.ScanAsync(folder).ConfigureAwait(true);
            foreach (var entry in entries)
            {
                FileScanResults.Add(new FileScanRow(entry));
            }

            ApplyCommunityMatches();
            if (entries.Count == 0)
            {
                FileScanStatus = "0 file(s) scanned locally. Hashes are not uploaded.";
            }
        }
#pragma warning disable CA1031 // The UI must show a scan failure instead of crashing.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            FileScanStatus = $"Scan failed: {exception.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private async Task UninstallModuleAsync(string? module)
    {
        if (string.IsNullOrWhiteSpace(module))
        {
            return;
        }

        if (DistributionContext.IsStorePackage &&
            (module.Equals("Blackbox", StringComparison.Ordinal) ||
             module.Equals("OriginTrail DKG", StringComparison.Ordinal)))
        {
            InstallStatusText = "This optional third-party module is not included in the Microsoft Store build.";
            return;
        }

        var message = module switch
        {
            "Blackbox" =>
                "Remove Axiom's Blackbox runtime, its command, the managed Hermes plugin, .hermes\\blackbox and the Blackbox login tasks? Other Hermes data and global packages are kept.",
            "OriginTrail DKG" =>
                "Remove the local DKG package and its testnet home? No global npm package is removed.",
            "Reputation provider" =>
                "Delete the stored VirusTotal API key and disable the provider?",
            "Community feed" =>
                "Delete the stored community feed URL and token?",
            _ => null,
        };

        if (message is null)
        {
            return;
        }

        var confirmed = await _ui.ConfirmAsync(
            "Uninstall optional module",
            message,
            "Remove",
            destructive: true,
            CancellationToken.None).ConfigureAwait(true);

        if (!confirmed)
        {
            return;
        }

        var protectedBefore = await Task.Run(() => _userStateProtection.Capture()).ConfigureAwait(true);
        var allowedChanges = new List<string>();
        var uninstallSucceeded = true;

        switch (module)
        {
            case "Blackbox":
                allowedChanges.Add(_codexProtection.HooksPath);
                allowedChanges.Add(_claudeProtection.SettingsPath);
                allowedChanges.Add(_antigravityProtection.HooksPath);
                allowedChanges.Add(_cursorProtection.HooksPath);
                allowedChanges.Add(_copilotProtection.HooksPath);
                allowedChanges.Add(_geminiProtection.SettingsPath);
                allowedChanges.Add(_windsurfProtection.HooksPath);
                allowedChanges.Add(_clineProtection.HookPath);
                allowedChanges.Add(_zCodeProtection.ConfigPath);
                allowedChanges.Add(_deepSeekProtection.HooksPath);
                allowedChanges.Add(_deepSeekProtection.PatchPath);
                allowedChanges.Add(_uninstaller.OpenCodePlugin);
                allowedChanges.Add(_uninstaller.OpenCodeV1Plugin);
                allowedChanges.Add(_uninstaller.OpenCodeLegacyPlugin);
                uninstallSucceeded = await Task.Run(
                    () => _uninstaller.UninstallBlackboxAndWait()).ConfigureAwait(true);
                InstallStatusText = uninstallSucceeded
                    ? "Blackbox uninstall finished."
                    : "Blackbox uninstall failed: " + (_uninstaller.LastError ?? "check the local log.");
                break;
            case "OriginTrail DKG":
                uninstallSucceeded = await Task.Run(
                    () => _uninstaller.UninstallDkgAndWait()).ConfigureAwait(true);
                InstallStatusText = uninstallSucceeded
                    ? "DKG uninstall finished."
                    : "DKG uninstall failed: " + (_uninstaller.LastError ?? "check the local log.");
                break;
            case "Reputation provider":
                allowedChanges.Add(_uninstaller.ReputationSettingsPath);
                await Task.Run(_uninstaller.RemoveReputationSettings).ConfigureAwait(true);
                _reputationSettings = new ReputationSettings(false, string.Empty);
                InstallStatusText = "VirusTotal key removed.";
                break;
            case "Community feed":
                allowedChanges.Add(_uninstaller.CommunitySettingsPath);
                await Task.Run(_uninstaller.RemoveCommunitySettings).ConfigureAwait(true);
                _communitySettings = new CommunityFeedSettings(false, string.Empty, string.Empty);
                _communityConnected = false;
                CommunityEntries.Clear();
                _notifiedCommunityHashes.Clear();
                ApplyCommunityMatches();
                InstallStatusText = "Community feed settings removed.";
                break;
        }

        var unexpectedChanges = await Task.Run(
            () => _userStateProtection.Verify(protectedBefore, allowedChanges)).ConfigureAwait(true);
        if (unexpectedChanges.Count > 0)
        {
            var restoreFailures = await Task.Run(
                () => _userStateProtection.Restore(protectedBefore, unexpectedChanges)).ConfigureAwait(true);
            InstallStatusText = restoreFailures.Count == 0
                ? $"Uninstall detected {unexpectedChanges.Count} protected user-state change(s) and restored them."
                : $"Uninstall detected {unexpectedChanges.Count} protected user-state change(s); " +
                  $"{restoreFailures.Count} could not be restored. Review agent sessions, projects, credentials and Antigravity history.";
        }

        await Task.Delay(500).ConfigureAwait(true);
        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task InstallAgentHooksAsync()
    {
        if (!IsAgentProtectionAvailable)
        {
            InstallStatusText = "Agent hook installation is not available in the Microsoft Store build.";
            return;
        }

        var choice = await _dialogs
            .ChooseAgentHookInstallationAsync(CancellationToken.None)
            .ConfigureAwait(true);
        if (choice is null)
        {
            InstallStatusText = "Agent hook installation cancelled. No agent files were changed.";
            return;
        }

        if (choice == false)
        {
            InstallStatusText = "Partial installation selected. No OpenCode, OpenChamber, Codex, Claude Code, Antigravity, Cursor, Copilot, Gemini, Windsurf, Cline, ZCode or DeepSeek Harness hook files were changed.";
            return;
        }

        var snapshot = await Task.Run(() => _userStateProtection.Capture()).ConfigureAwait(true);
        var openCode = _openCodeProtection.EnsureInstalled();
        var codex = _codexProtection.EnsureInstalled();
        var claude = _claudeProtection.EnsureInstalled();
        var antigravity = _antigravityProtection.EnsureInstalled();
        var cursor = _cursorProtection.EnsureInstalled();
        var copilot = _copilotProtection.EnsureInstalled();
        var gemini = _geminiProtection.EnsureInstalled();
        var windsurf = _windsurfProtection.EnsureInstalled();
        var cline = _clineProtection.EnsureInstalled();
        var zCode = _zCodeProtection.EnsureInstalled();
        var deepSeek = _deepSeekProtection.EnsureInstalled();

        var allowedHookChanges = new[]
        {
            _openCodeProtection.PluginPath,
            _openCodeProtection.V1PluginPath,
            _openCodeProtection.LegacyPluginPath,
            _openCodeProtection.BridgePath,
            _openCodeProtection.PreRenamePluginDirectory,
            _openCodeProtection.PreRenameV1PluginPath,
            _openCodeProtection.PreRenameSingularPluginPath,
            _openCodeProtection.PreRenameBridgePath,
            _codexProtection.HooksPath,
            _codexProtection.HookScriptPath,
            _claudeProtection.SettingsPath,
            _claudeProtection.HookScriptPath,
            _antigravityProtection.HooksPath,
            _antigravityProtection.HookScriptPath,
            _cursorProtection.HooksPath,
            _cursorProtection.HookScriptPath,
            _copilotProtection.HooksPath,
            _copilotProtection.HookScriptPath,
            _copilotProtection.PreRenameHooksPath,
            _geminiProtection.SettingsPath,
            _geminiProtection.HookScriptPath,
            _windsurfProtection.HooksPath,
            _windsurfProtection.HookScriptPath,
            _clineProtection.HookPath,
            _zCodeProtection.ConfigPath,
            _zCodeProtection.HookScriptPath,
            _deepSeekProtection.HooksPath,
            _deepSeekProtection.PatchPath,
            _deepSeekProtection.HookScriptPath,
        };
        var unexpectedChanges = await Task.Run(
            () => _userStateProtection.Verify(snapshot, allowedHookChanges)).ConfigureAwait(true);
        if (unexpectedChanges.Count > 0)
        {
            var restoreFailures = await Task.Run(
                () => _userStateProtection.Restore(snapshot, unexpectedChanges)).ConfigureAwait(true);
            InstallStatusText = restoreFailures.Count == 0
                ? $"Hook installation aborted: {unexpectedChanges.Count} protected user-state file(s) changed unexpectedly and were restored."
                : $"Hook installation aborted: {unexpectedChanges.Count} protected user-state change(s) detected; " +
                  $"{restoreFailures.Count} could not be restored. Review MCP, model, favorite, session and Antigravity history files.";
            await RefreshAsync().ConfigureAwait(true);
            return;
        }

        InstallStatusText =
            $"Hook install result: OpenCode/OpenChamber {(openCode ? "installed" : "skipped")}, " +
            $"Codex {(codex ? "installed" : "skipped")}, Claude Code {(claude ? "installed" : "skipped")}, " +
            $"Antigravity {(antigravity ? "installed" : "skipped")}, " +
            $"Cursor {(cursor ? "installed" : "skipped")}, GitHub Copilot CLI {(copilot ? "installed" : "skipped")}, " +
            $"Gemini CLI {(gemini ? "installed" : "skipped")}, Windsurf Cascade {(windsurf ? "installed" : "skipped")}, " +
            $"Cline {(cline ? "installed" : "skipped")}, ZCode {(zCode ? "installed" : "skipped")}, " +
            $"DeepSeek Harness {(deepSeek ? "installed" : "skipped")}. " +
            "Existing managed hook files are backed up beside the originals. " +
            "MCP server definitions, selected models, favorites, sessions and Antigravity history were not changed.";
        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task SetBlackboxModeAsync(string? mode)
    {
        if (mode is not ("audit" or "block"))
        {
            return;
        }

        var success = _blackboxMode.SetMode(mode);
        BlackboxModeText = mode;
        InstallStatusText = success
            ? $"Blackbox mode set to {mode}."
            : "Could not update the Blackbox mode. Is the Blackbox venv present?";

        await RefreshAsync().ConfigureAwait(true);
    }

    [RelayCommand]
    private void Restart() => _shell.Restart();

    [RelayCommand]
    private Task CopyScanHashAsync(FileScanRow? row) => CopyTextSafeAsync(row?.Sha256);

    [RelayCommand]
    private Task CopyScanPathAsync(FileScanRow? row) => CopyTextSafeAsync(row?.Path);

    [RelayCommand]
    private Task CopyCommunityHashAsync(CommunityFeedRow? row) => CopyTextSafeAsync(row?.Sha256);

    private async Task CopyTextSafeAsync(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "—")
        {
            return;
        }

        try
        {
            await _ui.CopyTextAsync(value, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or NotSupportedException or System.Runtime.InteropServices.ExternalException)
        {
        }
    }

    private static OptionalModuleStatus StoreModule(string detail) => new()
    {
        Status = "NOT INCLUDED",
        Detail = detail,
        IsConnected = false,
    };

    private void SeedCheckingState()
    {
        Modules.Add(CreateReputationModule());
        if (!DistributionContext.IsStorePackage)
        {
            var blackboxRuntime = _uninstaller.IsBlackboxRuntimeInstalled;
            var blackboxFiles = _uninstaller.HasBlackboxFiles;
            Modules.Add(new SecurityModule(
                "Blackbox",
                "CHECKING",
                "Looking for a local Blackbox dashboard on 127.0.0.1:9700.",
                "\uE7BA",
                false,
                true,
                blackboxRuntime ? "Start" : blackboxFiles ? "Repair" : "Install",
                blackboxFiles,
                _blackboxMode.IsAvailable,
                blackboxRuntime));
            var dkgAvailable = _installer.IsDkgAvailable;
            var dkgFiles = _uninstaller.HasDkgFiles;
            Modules.Add(new SecurityModule(
                "OriginTrail DKG",
                "CHECKING",
                "Looking for a local DKG node on 127.0.0.1:9200.",
                "\uE968",
                false,
                true,
                dkgAvailable ? "Start" : dkgFiles ? "Repair" : "Install",
                dkgFiles,
                false,
                dkgAvailable));
        }

        Modules.Add(CreateCommunityModule());
        Modules.Add(CreateFileScanningModule());
    }

    private SecurityModule CreateReputationModule()
    {
        var configured = _reputationSettings.Enabled && !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey);
        return new SecurityModule(
            "Reputation provider",
            ReputationStatus,
            ReputationDetail,
            "\uE9D9",
            configured,
            true,
            "Setup",
            _reputationSettings.Enabled || !string.IsNullOrWhiteSpace(_reputationSettings.ApiKey));
    }

    private SecurityModule CreateFileScanningModule() => new(
        "File scanning",
        "ON DEMAND",
        "Hashes folders locally (SHA-256) and checks them against your Community feed; VirusTotal VT Check is optional.",
        "\uE8A5",
        false,
        true,
        "Scan");

    private SecurityModule CreateCommunityModule() => new(
        "Community feed",
        CommunityStatus,
        CommunityDetail,
        "\uE774",
        _communityConnected,
        true,
        "Setup",
        IsCommunityConfigured);

    private async Task RefreshAgentsAsync(bool blackboxConnected, CancellationToken cancellationToken)
    {
        ProtectedAgents.Clear();

        if (!IsAgentProtectionAvailable)
        {
            AgentsStatusText = AgentStatusText;
            return;
        }

        var continuity = BlackboxLocalState.EvaluateContinuity();
        var guardAndRulesetAvailable = blackboxConnected ||
                                       (continuity.GuardAvailable && continuity.RulesetAvailable);

        // Status refresh is read-only. Startup provisioning handles Axiom-managed hooks separately.
        AddCodexAgents(guardAndRulesetAvailable);
        AddClaudeAgents(guardAndRulesetAvailable);
        AddAntigravityAgents(guardAndRulesetAvailable);
        AddCursorAgents(guardAndRulesetAvailable);
        AddCopilotAgents(guardAndRulesetAvailable);
        AddGeminiAgents(guardAndRulesetAvailable);
        AddWindsurfAgents(guardAndRulesetAvailable);
        AddClineAgents(guardAndRulesetAvailable);
        AddZCodeAgents(guardAndRulesetAvailable);
        AddDeepSeekAgents(guardAndRulesetAvailable);
        AddOpenCodeAgents(guardAndRulesetAvailable);

        if (!blackboxConnected)
        {
            if (guardAndRulesetAvailable)
            {
                AgentsStatusText = ProtectedAgents.Count == 0
                    ? $"Blackbox dashboard is offline; {continuity.Summary} No agent workspaces were detected."
                    : $"Blackbox dashboard is offline; local guard and cached ruleset remain active for hooked agents. " +
                      $"{continuity.Summary} Installed hooks alone are not proof of runtime blocking.";
            }
            else
            {
                AgentsStatusText = ProtectedAgents.Count == 0
                    ? $"Blackbox is not connected; no agent protection status is available. {continuity.Summary}"
                    : $"Blackbox local guard or ruleset is unavailable; detected agents are not protected by graph rules. {continuity.Summary}";
            }

            return;
        }

        try
        {
            using var response = await _blackboxClient
                .GetAsync("http://127.0.0.1:9700/api/attach-targets", cancellationToken)
                .ConfigureAwait(true);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content
                .ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(true);
            using var document = await JsonDocument
                .ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(true);

            cancellationToken.ThrowIfCancellationRequested();
            if (!document.RootElement.TryGetProperty("targets", out var targets) ||
                targets.ValueKind != JsonValueKind.Array)
            {
                AgentsStatusText = "Blackbox did not return an agent target list.";
                return;
            }

            foreach (var target in targets.EnumerateArray())
            {
                var kind = ReadString(target, "kind") ?? "agent";
                var path = ReadString(target, "target") ?? string.Empty;
                var isProtected = target.TryGetProperty("protected", out var protectedElement) &&
                                  protectedElement.ValueKind == JsonValueKind.True;
                var available = !target.TryGetProperty("available", out var availableElement) ||
                                availableElement.ValueKind != JsonValueKind.False;
                var reason = ReadString(target, "disabled_reason");

                var status = isProtected
                    ? "PROTECTED"
                    : available ? "DETECTED" : "NOT DETECTED";
                var detail = reason ?? (isProtected
                    ? "Workspace attached"
                    : available ? "Workspace detected; not attached" : "Not detected on this machine");

                ProtectedAgents.Add(new ProtectedAgent(kind, path, status, detail));
            }

            var runtimeObserved = ProtectedAgents.Count(agent =>
                agent.Status is "VERIFIED BLOCKING" or "HOOK LOADED" or "AUDIT ONLY");
            AgentsStatusText = ProtectedAgents.Count == 0
                ? "No agent workspace was reported."
                : $"Hook activity observed in {runtimeObserved} of {ProtectedAgents.Count} recognized agent workspaces. " +
                  "Installed hooks alone are not proof of runtime blocking.";
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested && exception is
            HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            AgentsStatusText = $"Could not read Blackbox agent targets: {exception.Message}";
        }
    }

    private void AddOpenCodeAgents(bool blackboxConnected)
    {
        if (!_openCodeProtection.IsOpenCodeDetected)
        {
            return;
        }

        var installed = _openCodeProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("opencode", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !installed
            ? "OpenCode config detected; guard plugin not installed or a user plugin occupies the path."
            : evidence is null
                ? "Guard plugin installed; no hook invocation has been observed yet."
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "opencode",
            _openCodeProtection.ConfigDirectory,
            status,
            detail));

        if (_openCodeProtection.IsOpenChamberDetected)
        {
            var openChamberStatus = AgentProtectionClassifier.Classify(
                detected: true,
                hookConfigured: installed,
                runtimeObserved: false,
                failureObserved: false,
                blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
            ProtectedAgents.Add(new ProtectedAgent(
                "openchamber",
                _openCodeProtection.OpenChamberPath,
                openChamberStatus,
                "OpenChamber detected, but no OpenChamber-specific runtime evidence exists. " +
                "It shares the OpenCode backend; protection is not verified until a test runs in OpenChamber itself."));
        }
    }

    private void AddCodexAgents(bool blackboxConnected)
    {
        if (!_codexProtection.IsCodexDetected)
        {
            return;
        }

        var installed = _codexProtection.IsInstalled;
        var trust = _codexProtection.TrustState;
        var processRunning = AgentProcessProbe.IsRunning("codex");
        var evidence = _agentEvidence.Latest("codex", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected,
            auditOnly: IsAuditOnly,
            trustRequired: trust.TrustRequired,
            verifiedBlocking: _verifiedBlockingAgents.Contains("codex"));
        var detail = !installed
            ? "Codex config detected; lifecycle hooks are missing or malformed."
            : trust.TrustRequired
                ? "Lifecycle hooks are installed, but Codex has not trusted these exact definitions. Open Codex, run /hooks and trust the Axiom hooks."
                : _verifiedBlockingAgents.Contains("codex")
                    ? "Guard-level canary test blocked the benign read. The real Codex process was not exercised."
                    : evidence is null
                        ? (processRunning
                            ? "Codex is running; the hooks are installed and trusted, but no runtime invocation has been observed yet."
                            : "Hooks are installed and trusted; start Codex to verify runtime loading.")
                        : evidence.IsFailure
                            ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                            : $"Runtime observed: {evidence.EventType} at {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end host blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "codex",
            _codexProtection.HooksPath,
            status,
            detail)
        {
            ProcessRunning = processRunning,
            TrustRequired = trust.TrustRequired,
        });
    }

    private void AddAntigravityAgents(bool blackboxConnected)
    {
        if (!_antigravityProtection.IsAntigravityDetected)
        {
            return;
        }

        var installed = _antigravityProtection.IsInstalled;
        var processRunning = AgentProcessProbe.IsRunning("antigravity");
        var evidence = _agentEvidence.Latest("antigravity", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected,
            auditOnly: IsAuditOnly);
        var detail = !installed
            ? "Antigravity config detected; the Axiom PreToolUse hook is missing or malformed."
            : evidence is null
                ? (processRunning
                    ? "Antigravity is running; the hook is installed but no invocation has been observed. Restart Antigravity if it was started before the hook."
                    : "Hook is installed; start Antigravity to verify runtime loading.")
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "antigravity",
            _antigravityProtection.HooksPath,
            status,
            detail)
        {
            ProcessRunning = processRunning,
        });
    }

    private void AddClaudeAgents(bool blackboxConnected)
    {
        if (!_claudeProtection.IsClaudeDetected)
        {
            return;
        }

        var installed = _claudeProtection.IsInstalled;
        var processRunning = AgentProcessProbe.IsRunning("claude");
        var evidence = _agentEvidence.Latest("claude", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly, verifiedBlocking: _verifiedBlockingAgents.Contains("claude"));
        var detail = !installed
            ? "Claude Code config detected; lifecycle hooks are missing or malformed."
            : _verifiedBlockingAgents.Contains("claude")
                ? "Guard-level canary test blocked the benign read. The real Claude Code process was not exercised."
                : evidence is null
                    ? (processRunning
                        ? "Claude Code is running; hooks are installed, but no runtime invocation has been observed yet."
                        : "Hooks are installed; start Claude Code to verify runtime loading.")
                    : evidence.IsFailure
                        ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                        : $"Runtime observed: {evidence.EventType} at {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end host blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "claude",
            _claudeProtection.SettingsPath,
            status,
            detail)
        {
            ProcessRunning = processRunning,
        });
    }

    private void AddCursorAgents(bool blackboxConnected)
    {
        if (!_cursorProtection.IsCursorDetected)
        {
            return;
        }

        var installed = _cursorProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("cursor", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !installed
            ? "Cursor config detected; preToolUse hook is missing or malformed."
            : evidence is null
                ? "Hook configuration detected; runtime not verified. Restart Cursor if it was already running."
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "cursor",
            _cursorProtection.HooksPath,
            status,
            detail));
    }

    private void AddCopilotAgents(bool blackboxConnected)
    {
        if (!_copilotProtection.IsCopilotDetected)
        {
            return;
        }

        var installed = _copilotProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("copilot", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !installed
            ? "GitHub Copilot CLI config detected; preToolUse hook is missing or malformed."
            : evidence is null
                ? "Hook configuration detected; runtime not verified. Restart Copilot CLI if it was already running."
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); Copilot preToolUse is fail-closed, so check the hook."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "copilot",
            _copilotProtection.HooksPath,
            status,
            detail));
    }

    private void AddGeminiAgents(bool blackboxConnected)
    {
        if (!_geminiProtection.IsGeminiDetected)
        {
            return;
        }

        var installed = _geminiProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("gemini", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !installed
            ? "Gemini settings detected; BeforeTool hook is missing or malformed. Antigravity CLI may use a different hook surface."
            : evidence is null
                ? "Gemini hook configuration detected; runtime not verified. Antigravity CLI is not assumed to share this surface."
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. Antigravity history/MCP files were not modified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "gemini",
            _geminiProtection.SettingsPath,
            status,
            detail));
    }

    private void AddWindsurfAgents(bool blackboxConnected)
    {
        if (!_windsurfProtection.IsWindsurfDetected)
        {
            return;
        }

        var installed = _windsurfProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("windsurf", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !installed
            ? "Windsurf config detected; Cascade pre-hooks are missing or malformed."
            : evidence is null
                ? "Hook configuration detected; runtime not verified. Restart Cascade if it was already running."
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); Cascade blocks only on exit code 2."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "windsurf",
            _windsurfProtection.HooksPath,
            status,
            detail));
    }

    private void AddClineAgents(bool blackboxConnected)
    {
        if (!_clineProtection.IsClineDetected)
        {
            return;
        }

        var installed = _clineProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("cline", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !installed
            ? "Cline directory detected; global PreToolUse.py hook is missing or user-authored."
            : evidence is null
                ? "Hook file detected; runtime not verified. Cline must have hooks enabled and may need a restart."
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "cline",
            _clineProtection.HookPath,
            status,
            detail));
    }

    private void AddZCodeAgents(bool blackboxConnected)
    {
        if (!_zCodeProtection.IsZCodeDetected)
        {
            return;
        }

        var installed = _zCodeProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("zcode", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !installed
            ? "ZCode config detected; the user-scope Axiom hook entries are missing or malformed."
            : evidence is null
                ? "Hook config detected; runtime not verified. ZCode snapshots hooks at session start, so restart it or start a new session."
                : evidence.IsFailure
                    ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                    : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "zcode",
            _zCodeProtection.ConfigPath,
            status,
            detail));
    }

    private void AddDeepSeekAgents(bool blackboxConnected)
    {
        if (!_deepSeekProtection.IsDeepSeekDetected)
        {
            return;
        }

        var configured = _deepSeekProtection.IsConfigured;
        var installed = _deepSeekProtection.IsInstalled;
        var evidence = _agentEvidence.Latest("deepseek", EvidenceLifetime);
        var status = AgentProtectionClassifier.Classify(
            detected: true,
            hookConfigured: installed,
            runtimeObserved: evidence is not null,
            failureObserved: evidence?.IsFailure == true,
            blackboxAvailable: blackboxConnected, auditOnly: IsAuditOnly);
        var detail = !configured
            ? "DeepSeek Harness home detected; the Axiom hook file or bridge mount is missing."
            : !_deepSeekProtection.IsBridgeInstalled
                ? "Axiom hooks are prepared, but DeepSeek's dsh-hooks-claude-code bridge is not installed in a DSH profile."
                : _deepSeekProtection.BridgeVersionMismatch is { } bridgeMismatch
                    ? $"Axiom hooks are prepared, but the hook bridge does not match the DSH runtime ({bridgeMismatch}). Install @deepseek-ai/dsh-hooks-claude-code at the runtime's version."
                    : !_deepSeekProtection.NodeRequirementMet
                        ? $"Hook bridge installed, but Node {_deepSeekProtection.NodeVersion} is below the DSH engine requirement ({_deepSeekProtection.NodeRequirement}); dsh may refuse to start."
                        : evidence is null
                            ? "Hook config and bridge mount detected; runtime not verified. Restart DSH."
                            : evidence.IsFailure
                                ? $"Hook observed but guard failed ({evidence.ErrorCode}); fail-open means protection is degraded."
                                : $"Runtime observed: {evidence.EventType} · {evidence.Tool} · {evidence.Timestamp.ToLocalTime():HH:mm:ss}. End-to-end blocking is not verified.";

        ProtectedAgents.Add(new ProtectedAgent(
            "deepseek",
            _deepSeekProtection.HooksPath,
            status,
            detail));
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private void ReplaceCommunityModule()
    {
        for (var index = 0; index < Modules.Count; index++)
        {
            if (Modules[index].Name == "Community feed")
            {
                Modules[index] = CreateCommunityModule();
                break;
            }
        }

        NotifyStatusProperties();
    }

    private void NotifyStatusProperties()
    {
        OnPropertyChanged(nameof(StatusTitle));
        OnPropertyChanged(nameof(StatusBadge));
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(AgentStatusTitle));
        OnPropertyChanged(nameof(AgentStatusBadge));
        OnPropertyChanged(nameof(AgentStatusText));
        OnPropertyChanged(nameof(SecurityStatusTitle));
        OnPropertyChanged(nameof(SecurityStatusBadge));
        OnPropertyChanged(nameof(SecurityStatusText));
    }

    private void Rebuild(OptionalModuleStatus dkg, OptionalModuleStatus blackbox)
    {
        ApplyBrandLabels(dkg.IsConnected, blackbox.IsConnected);
        Modules.Clear();
        Modules.Add(CreateReputationModule());
        if (!DistributionContext.IsStorePackage)
        {
            var blackboxRuntime = _uninstaller.IsBlackboxRuntimeInstalled;
            var blackboxFiles = _uninstaller.HasBlackboxFiles;
            var blackboxDetail = !blackbox.IsConnected && !blackboxRuntime && blackboxFiles
                ? $"{blackbox.Detail} Incomplete Blackbox installation detected (venv is missing) — click Repair to reinstall."
                : blackbox.Detail;
            Modules.Add(new SecurityModule(
                "Blackbox",
                blackbox.Status,
                blackboxDetail,
                "\uE7BA",
                blackbox.IsConnected,
                !blackbox.IsConnected,
                blackboxRuntime ? "Start" : blackboxFiles ? "Repair" : "Install",
                blackboxFiles,
                _blackboxMode.IsAvailable,
                blackboxRuntime));
            var dkgAvailable = _installer.IsDkgAvailable;
            var dkgFiles = _uninstaller.HasDkgFiles;
            var dkgDetail = !dkg.IsConnected && !dkgAvailable && dkgFiles
                ? $"{dkg.Detail} Incomplete DKG installation detected (DKG CLI is missing) — click Repair to reinstall."
                : dkg.Detail;
            Modules.Add(new SecurityModule(
                "OriginTrail DKG",
                dkg.Status,
                dkgDetail,
                "\uE968",
                dkg.IsConnected,
                !dkg.IsConnected,
                dkgAvailable ? "Start" : dkgFiles ? "Repair" : "Install",
                dkgFiles,
                false,
                dkgAvailable));
        }

        Modules.Add(CreateCommunityModule());
        Modules.Add(CreateFileScanningModule());
    }
}
