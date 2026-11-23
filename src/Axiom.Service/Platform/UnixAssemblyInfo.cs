// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

// The net10.0 build of the service is the macOS launchd daemon (axiomd); the Windows service is
// the net10.0-windows build. Declaring it lets the platform analyzer check the Unix-only adapters.
[assembly: UnsupportedOSPlatform("windows")]

// Composition tests of the Unix daemon (tests/Axiom.Service.Unix.Tests).
[assembly: InternalsVisibleTo("Axiom.Service.Unix.Tests")]
