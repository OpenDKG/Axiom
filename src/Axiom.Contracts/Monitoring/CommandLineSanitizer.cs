// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
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

    /// <summary>Returned in place of a command line when a pattern runs out of time.</summary>
    public const string TimeoutPlaceholder = "[sanitiser timeout]";

    private static readonly TimeSpan DefaultMatchTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly ConcurrentDictionary<TimeSpan, Lazy<Rules>> RuleSets = new();

    // -u user:password, --user=user:password, --proxy-user "user:pass word"
    private const string UserFlag = @"(?<![\w-])(?:-u|--user|--proxy-user)(?:\s+|=)";

    /// <param name="commandLine">Raw command line.</param>
    /// <param name="homeDirectory">
    /// Home directory of the process owner. A Windows path is replaced with <c>%USERPROFILE%</c>,
    /// a Unix path with <c>~</c>.
    /// </param>
    public static string Sanitize(string? commandLine, string? homeDirectory = null) =>
        Sanitize(commandLine, homeDirectory, DefaultMatchTimeout);

    /// <param name="commandLine">Raw command line.</param>
    /// <param name="homeDirectory">Home directory of the process owner.</param>
    /// <param name="matchTimeout">
    /// The longest one pattern may run, or <see cref="Regex.InfiniteMatchTimeout"/> for no limit.
    /// </param>
    public static string Sanitize(string? commandLine, string? homeDirectory, TimeSpan matchTimeout) =>
        Sanitize(commandLine, homeDirectory, matchTimeout, beforeRules: null);

    // beforeRules lets a test end the work the way a timed-out pattern does, whatever the machine's speed.
    internal static string Sanitize(string? commandLine, string? homeDirectory, TimeSpan matchTimeout, Action? beforeRules)
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
            var rules = RuleSets.GetOrAdd(matchTimeout, static timeout => new Lazy<Rules>(() => new Rules(timeout))).Value;
            beforeRules?.Invoke();
            text = rules.UrlUserInfo.Replace(text, Mask + "@");
            text = rules.Authorization.Replace(text, "${keep}" + Mask);
            text = rules.Assignment.Replace(text, "${keep}" + Mask);
            text = rules.Flag.Replace(text, "${keep}" + Mask);
            text = rules.QuotedUserPassword.Replace(text, "${keep}" + Mask);
            text = rules.UserPassword.Replace(text, "${keep}" + Mask);
            text = rules.Setter.Replace(text, "${keep}" + Mask);
            text = rules.TokenShape.Replace(text, Mask);
            text = ShortenHome(text, homeDirectory, matchTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            // A partly processed line may still hold a value. The placeholder says why the line is missing.
            return TimeoutPlaceholder;
        }

        return text.Length <= MaxLength ? text : text[..MaxLength] + Ellipsis;
    }

    private static string ShortenHome(string text, string? homeDirectory, TimeSpan matchTimeout)
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
            matchTimeout);
    }

    // The patterns with one match timeout. A set is built once for each timeout in use.
    private sealed class Rules(TimeSpan matchTimeout)
    {
        // scheme://user:password@host
        public Regex UrlUserInfo { get; } = Create(@"(?<=://)[^/\s""'?#:@]*:[^/\s""'?#]*@", matchTimeout);

        // Authorization: Bearer <value>, --authorization <value>, bearer <value>
        public Regex Authorization { get; } = Create(
            @"(?<![A-Za-z0-9_])(?<keep>(?:authorization|bearer)(?![\w-])(?:\s*[:=]\s*|\s+)(?:(?:bearer|basic|token|apikey)\s+)?)" +
            Value, matchTimeout);

        // password=<value>, AWS_SECRET_ACCESS_KEY=<value>, ?access_token=<value>, api-key: <value>
        public Regex Assignment { get; } = Create(
            @"(?<!\w)(?<keep>(?>\w+(?:-key)?)(?<=password|passwd|pwd|token|secret|apikey|api[_-]key|_key)\s*[=:]\s*)" +
            Value, matchTimeout);

        // --password <value>, --api-key <value>, --client-secret <value>
        public Regex Flag { get; } = Create(
            @"(?<![\w-])(?<keep>--?(?>[\w-]+)(?<=password|passwd|pwd|token|secret|apikey|[_-]key)\s+)" + Value, matchTimeout);

        public Regex QuotedUserPassword { get; } = Create(
            @"(?<keep>" + UserFlag + @"(?<quote>[""'])(?:(?!\k<quote>)[^:])*:)(?:(?!\k<quote>)[^…])+", matchTimeout);

        // The password may not start with "/", so that "-u https://host" is left alone.
        public Regex UserPassword { get; } = Create(
            @"(?<keep>" + UserFlag + @"[^\s""':=/-]*:)[^\s""'…/][^\s""'…]*", matchTimeout);

        // set <name containing secret, password, token or key> <value>
        public Regex Setter { get; } = Create(
            @"(?<![\w.-])(?<keep>set\s+(?=[\w.-]*(?:secret|password|passwd|token|key))(?>[\w.-]+)\s+)" + Value, matchTimeout);

        public Regex TokenShape { get; } = Create(
            @"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{6,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|" +
            @"xox[abprs]-[A-Za-z0-9-]{8,}|(?-i:AKIA[0-9A-Z]{16})|" +
            @"(?-i:eyJ)[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", matchTimeout);

        private static Regex Create(string pattern, TimeSpan timeout) =>
            new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, timeout);
    }
}
