// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.Unix.Diagnostics;

/// <summary>One line of <c>axiomd --doctor</c> (macOS and Linux share the format and exit code rule).</summary>
public sealed record DoctorCheck(string Status, string Name, string Detail)
{
    public const string Pass = "PASS";

    public const string Warn = "WARN";

    public const string Fail = "FAIL";

    public const string Skip = "SKIP";

    public bool IsProblem => Status is Warn or Fail;

    public override string ToString() => $"{Status,-4} {Name}: {Detail}";
}
