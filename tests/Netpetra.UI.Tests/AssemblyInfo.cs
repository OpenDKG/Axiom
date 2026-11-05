// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit;

// DistributionContext is process-wide state set by the Desktop host. Tests that switch it to Store
// mode must not overlap with adapter or uninstaller tests in another test class.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
