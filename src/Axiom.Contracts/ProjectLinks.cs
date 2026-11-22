// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts;

/// <summary>Public destinations for the desktop application.</summary>
public static class ProjectLinks
{
    private const string RepositoryPath = "OpenDKG/Axiom";

    public const string Website = "https://opendkg.org/axiom/";
    public const string PrivacyPolicy = "https://opendkg.org/privacy/";
    public const string Repository = "https://github.com/" + RepositoryPath;
    public const string NewIssue = Repository + "/issues/new/choose";
    public const string Releases = Repository + "/releases";
    public const string LatestReleaseApi = "https://api.github.com/repos/" + RepositoryPath + "/releases/latest";
}
