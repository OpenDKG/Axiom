// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Xunit;

namespace Axiom.Core.Tests;

/// <summary>
/// Gate B (#441): the machine-wide protection settings file is owner-only (0600) on Unix. On
/// Windows the file mode is not touched (ProgramData ACLs), so the check returns early there.
/// </summary>
public sealed class ProtectionSettingsFileModeTests
{
    [Fact]
    public void Saved_settings_are_owner_only_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var path = Path.Combine(Path.GetTempPath(), $"axiom-protection-mode-{Guid.NewGuid():N}.json");
        try
        {
            Assert.True(new ProtectionSettingsStore(path).Save(new ProtectionSettings { Enabled = true }));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
