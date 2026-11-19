// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.Versioning;

// The macOS infrastructure (Unix sockets, libproc, networksetup) is tested on macOS and Linux only.
[assembly: UnsupportedOSPlatform("windows")]
