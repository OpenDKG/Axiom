// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Management;
using Axiom.Core.Enforcement;
using Axiom.Infrastructure.Windows.ProcessIdentity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Axiom.Service;

/// <summary>
/// F-19 part B host: subscribes to Windows process-start events for the service lifetime, applies
/// the spawn policy/de-duplication and appends Record/Block rows to
/// <c>process-spawn-audit.jsonl</c> (under <c>%ProgramData%\Axiom</c> when running non-interactively
/// as a service, or <c>%LOCALAPPDATA%\Axiom</c> interactively). A failure to start the WMI feed is
/// logged and never stops the service.
/// </summary>
public sealed partial class ProcessSpawnAuditWorker : BackgroundService
{
    private readonly ILogger<ProcessSpawnAuditWorker> _logger;
    private readonly string _auditPath;

    public ProcessSpawnAuditWorker(ILogger<ProcessSpawnAuditWorker> logger)
        : this(logger, PrivacyShieldPaths.Resolve("process-spawn-audit.jsonl"))
    {
    }

    internal ProcessSpawnAuditWorker(ILogger<ProcessSpawnAuditWorker> logger, string auditPath)
    {
        _logger = logger;
        _auditPath = auditPath;
    }

    public string AuditPath => _auditPath;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ProcessSpawnAuditRuntime? runtime = null;
        StreamWriter? writer = null;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_auditPath) ?? ".");
            writer = new StreamWriter(
                new FileStream(_auditPath, FileMode.Append, FileAccess.Write, FileShare.Read),
                new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
            {
                AutoFlush = true,
            };

            var handler = new ProcessSpawnAuditHandler(
                new AgentProcessSpawnMonitor(),
                new JsonLinesProcessSpawnSink(writer));
            runtime = new ProcessSpawnAuditRuntime(
                new WmiProcessStartSource(ResolveImagePath),
                handler);
            runtime.Start();
            LogStarted(_auditPath);
        }
        catch (Exception exception) when (
            exception is ManagementException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            runtime?.Dispose();
            runtime = null;
            if (writer is not null)
            {
                await writer.DisposeAsync().ConfigureAwait(false);
                writer = null;
            }

            LogStartFailed(exception);
        }

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            runtime?.Dispose();
            if (writer is not null)
            {
                await writer.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "Process-spawn audit started; rows are appended to {Path}.")]
    private partial void LogStarted(string path);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Process-spawn audit could not start; the service continues without it.")]
    private partial void LogStartFailed(Exception exception);

    private static string? ResolveImagePath(int processId)
    {
        try
        {
            var query = string.Create(
                CultureInfo.InvariantCulture,
                $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
            using var searcher = new ManagementObjectSearcher(query);
            using var results = searcher.Get();
            foreach (var item in results)
            {
                using var process = item as ManagementObject;
                return process?["ExecutablePath"] as string;
            }
        }
        catch (ManagementException)
        {
        }

        return null;
    }
}
