// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.RegularExpressions;

namespace Axiom.Contracts.Monitoring;

/// <summary>
/// Masks recognised credential forms in a process command line, shortens the home directory and
/// caps the length. Used by every platform that reports command lines. It works on known
/// patterns, so it cannot promise that a command line holds nothing sensitive. Sanitising its own
/// output changes nothing.
/// </summary>
public static class CommandLineSanitizer
{
    /// <summary>Longer results are cut here and marked with an ellipsis.</summary>
    public const int MaxLength = 512;

    private const int MaxInputLength = 32 * 1024;

    private const string Mask = "***";

    private const char Ellipsis = '…';

    // A quoted value (or the rest of the line when the quote is never closed), else one word.
    private const string Value = @"(?:""(?:\\.|[^""\\])*""|'[^']*'|[""'][^…]*|[^\s""'…]+)";

    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(250);

    // scheme://user:password@host
    private static readonly Regex UrlUserInfo = Create(@"(?<=://)[^/\s""'?#:@]*:[^/\s""'?#]*@");

    // Authorization: Bearer <value>, --authorization <value>, bearer <value>
    private static readonly Regex Authorization = Create(
        @"(?<![A-Za-z0-9_])(?<keep>(?:authorization|bearer)(?![\w-])(?:\s*[:=]\s*|\s+)(?:(?:bearer|basic|token|apikey)\s+)?)" +
        Value);

    // password=<value>, AWS_SECRET_ACCESS_KEY=<value>, ?access_token=<value>, api-key: <value>
    private static readonly Regex Assignment = Create(
        @"(?<!\w)(?<keep>(?>\w+(?:-key)?)(?<=password|passwd|pwd|token|secret|apikey|api[_-]key|_key)\s*[=:]\s*)" +
        Value);

    // --password <value>, --api-key <value>, --client-secret <value>
    private static readonly Regex Flag = Create(
        @"(?<![\w-])(?<keep>--?(?>[\w-]+)(?<=password|passwd|pwd|token|secret|apikey|[_-]key)\s+)" + Value);

    // -u user:password, --user=user:password, --proxy-user "user:pass word"
    private const string UserFlag = @"(?<![\w-])(?:-u|--user|--proxy-user)(?:\s+|=)";

    private static readonly Regex QuotedUserPassword = Create(
        @"(?<keep>" + UserFlag + @"(?<quote>[""'])(?:(?!\k<quote>)[^:])*:)(?:(?!\k<quote>)[^…])+");

    // The password may not start with "/", so that "-u https://host" is left alone.
    private static readonly Regex UserPassword = Create(
        @"(?<keep>" + UserFlag + @"[^\s""':=/-]*:)[^\s""'…/][^\s""'…]*");

    // set <name containing secret, password, token or key> <value>
    private static readonly Regex Setter = Create(
        @"(?<![\w.-])(?<keep>set\s+(?=[\w.-]*(?:secret|password|passwd|token|key))(?>[\w.-]+)\s+)" + Value);

    private static readonly Regex TokenShape = Create(
        @"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{6,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|" +
        @"xox[abprs]-[A-Za-z0-9-]{8,}|(?-i:AKIA[0-9A-Z]{16})|" +
        @"(?-i:eyJ)[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)");

    /// <param name="commandLine">Raw command line.</param>
    /// <param name="homeDirectory">
    /// Home directory of the process owner. A Windows path is replaced with <c>%USERPROFILE%</c>,
    /// a Unix path with <c>~</c>.
    /// </param>
    public static string Sanitize(string? commandLine, string? homeDirectory = null)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return string.Empty;
        }

        var text = commandLine.Trim();
        if (text.Length > MaxInputLength)
        {
            text = text[..MaxInputLength];
        }

        try
        {
            text = UrlUserInfo.Replace(text, Mask + "@");
            text = Authorization.Replace(text, "${keep}" + Mask);
            text = Assignment.Replace(text, "${keep}" + Mask);
            text = Flag.Replace(text, "${keep}" + Mask);
            text = QuotedUserPassword.Replace(text, "${keep}" + Mask);
            text = UserPassword.Replace(text, "${keep}" + Mask);
            text = Setter.Replace(text, "${keep}" + Mask);
            text = TokenShape.Replace(text, Mask);
            text = ShortenHome(text, homeDirectory);
        }
        catch (RegexMatchTimeoutException)
        {
            // Nothing is better than a partly processed line.
            return string.Empty;
        }

        return text.Length <= MaxLength ? text : text[..MaxLength] + Ellipsis;
    }

    private static string ShortenHome(string text, string? homeDirectory)
    {
        var home = homeDirectory?.Trim().TrimEnd('/', '\\') ?? string.Empty;
        var isWindowsPath = home.Length > 2 && (home[1] == ':' || home.StartsWith(@"\\", StringComparison.Ordinal));
        // A root directory ("/", "C:\") is not a home worth hiding.
        if (home.Length < 2 || (!isWindowsPath && home[0] != '/'))
        {
            return text;
        }

        var options = RegexOptions.CultureInvariant | (isWindowsPath ? RegexOptions.IgnoreCase : RegexOptions.None);
        return Regex.Replace(
            text,
            Regex.Escape(home) + @"(?=$|[\\/\s""'…:;,=)])",
            isWindowsPath ? "%USERPROFILE%" : "~",
            options,
            MatchTimeout);
    }

    private static Regex Create(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, MatchTimeout);
}
