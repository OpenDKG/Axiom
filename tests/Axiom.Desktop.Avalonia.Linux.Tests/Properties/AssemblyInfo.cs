// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.Versioning;

// The Linux host only ever runs on Linux; this lets the Unix file-mode and signal APIs pass CA1416.
[assembly: SupportedOSPlatform("linux")]
