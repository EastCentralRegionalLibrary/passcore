using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Guards the two logging rules the providers are built around: every log
/// statement goes through a <c>LoggerMessage.Define</c> delegate with an
/// allocated EventId, and an EventId means exactly one thing everywhere.
///
/// <para>The second rule is the one that needs a test. Provider selection is
/// build-time, so an AD-built and an LDAP-built instance never share a process
/// — but their logs are routinely aggregated together, so a number reused
/// across providers silently merges two unrelated conditions in whatever the
/// operator greps. Nothing in the compiler notices; only the registry comment in
/// <see cref="PasswordChangeProviderBase"/> records the allocation, and a
/// comment cannot enforce itself.</para>
///
/// <para>Scanning source rather than reflecting over the assemblies is
/// deliberate: the AD provider is <c>net8.0-windows</c> inside
/// <c>#if WINDOWS</c> and cannot be loaded here at all, so half the allocation
/// would be invisible to a runtime check.</para>
/// </summary>
public class LoggingConventionAuditTests
{
    private const string RegistryRelativePath =
        "src/Unosquare.PassCore.Common/PasswordChangeProviderBase.cs";

    private static readonly string[] ProviderPaths =
    [
        "src/Zyborg.PassCore.PasswordProvider.LDAP/LdapPasswordChangeProvider.cs",
        "src/Unosquare.PassCore.PasswordProvider/PasswordChangeProvider.cs",
    ];

    private static readonly Regex EventIdDeclaration =
        new(@"new EventId\(\s*(?<id>\d+)", RegexOptions.CultureInvariant);

    /// <summary>Ad-hoc <c>ILogger</c> extension calls, which bypass the delegate convention (and trip CA1848).</summary>
    private static readonly Regex AdHocLoggerCall =
        new(@"Logger\.Log(Trace|Debug|Information|Warning|Error|Critical)\s*\(", RegexOptions.CultureInvariant);

    [Fact]
    public void EveryEventId_IsAllocatedExactlyOnce()
    {
        var byId = new Dictionary<int, List<string>>();

        foreach (var (relativePath, source) in SolutionSources())
        {
            foreach (Match match in EventIdDeclaration.Matches(source))
            {
                var id = int.Parse(match.Groups["id"].Value, System.Globalization.CultureInfo.InvariantCulture);
                if (!byId.TryGetValue(id, out var sites))
                    byId[id] = sites = new List<string>();

                sites.Add(relativePath);
            }
        }

        var duplicates = byId
            .Where(entry => entry.Value.Count > 1)
            .Select(entry => $"EventId {entry.Key} declared in: {string.Join(", ", entry.Value)}")
            .ToList();

        Assert.True(
            duplicates.Count == 0,
            "An EventId is declared more than once. Provider logs are aggregated together, so a reused " +
            "number merges two unrelated conditions for whoever is reading them:\n  " +
            string.Join("\n  ", duplicates));
    }

    /// <summary>
    /// 105 logged a group-enumeration failure as an expected Debug-level
    /// fallback. That fallback no longer exists — such a failure now leaves
    /// membership undetermined and is reported via <c>ServiceAccountFailure</c>
    /// (111) — and the ID stays retired rather than being recycled, so a
    /// historical log search for it cannot turn up something unrelated.
    /// </summary>
    [Fact]
    public void RetiredEventId105_IsNotAllocatedAnywhere()
    {
        var offenders = SolutionSources()
            .Where(file => EventIdDeclaration.Matches(file.Source)
                .Any(m => m.Groups["id"].Value == "105"))
            .Select(file => file.RelativePath)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"EventId 105 is retired but was allocated in: {string.Join(", ", offenders)}.");
    }

    /// <summary>
    /// Every allocated ID has to sit inside a range the registry declares, and
    /// each range's "next free" has to be one past its end. Adding a delegate
    /// without updating the registry fails here rather than quietly drifting.
    /// </summary>
    [Fact]
    public void RegistryRanges_CoverEveryAllocatedEventId_AndDeclareTheCorrectNextFree()
    {
        var ranges = DeclaredRanges();
        Assert.NotEmpty(ranges);

        foreach (var (low, high, next) in ranges)
        {
            Assert.True(
                next == high + 1,
                $"Registry range {low}-{high} declares 'next: {next}', but the next free number after " +
                $"{high} is {high + 1}. Update the range or the next-free value in {RegistryRelativePath}.");
        }

        foreach (var (relativePath, source) in SolutionSources())
        {
            foreach (Match match in EventIdDeclaration.Matches(source))
            {
                var id = int.Parse(match.Groups["id"].Value, System.Globalization.CultureInfo.InvariantCulture);

                Assert.True(
                    ranges.Any(r => id >= r.Low && id <= r.High),
                    $"EventId {id} in {relativePath} falls outside every range declared in the allocation " +
                    $"registry in {RegistryRelativePath}. Extend the appropriate range and its next-free " +
                    "value, or take a number from within one.");
            }
        }
    }

    /// <summary>
    /// Every <c>LoggerMessage.Define</c> format string must contain exactly as many
    /// placeholder occurrences as the call has type arguments.
    ///
    /// <para><b>Occurrences, not distinct names.</b> Repeating <c>{Host}</c> later in
    /// a message — natural enough when the sentence reads better for it — makes the
    /// count disagree, and <c>Define</c> throws <c>ArgumentException</c>. These are
    /// <c>static readonly</c> fields, so that surfaces as a
    /// <c>TypeInitializationException</c> the first time the provider is
    /// constructed: the whole application fails to start, and the log line that
    /// caused it never appears anywhere.</para>
    ///
    /// <para>Nothing in the compiler notices, and no existing test could: this is a
    /// runtime check inside a static initializer, and the AD provider is
    /// <c>net8.0-windows</c> inside <c>#if WINDOWS</c> and cannot be loaded here at
    /// all. It was found by a CI smoke test crashing at startup, which is the
    /// latest and most expensive place to find it. Reading the source is the only
    /// check available before then.</para>
    /// </summary>
    [Fact]
    public void EveryLoggerMessageDefine_HasOneFormatPlaceholderPerTypeArgument()
    {
        var offenders = new List<string>();

        foreach (var (relativePath, source) in SolutionSources())
        {
            foreach (var (typeArguments, placeholders, index) in LoggerMessageDefinitions(source))
            {
                if (typeArguments != placeholders)
                {
                    offenders.Add(
                        $"{relativePath} at offset {index}: {typeArguments} type argument(s) but " +
                        $"{placeholders} placeholder occurrence(s) in the format string.");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "A LoggerMessage.Define format string does not have one placeholder occurrence per type " +
            "argument. Define counts occurrences rather than distinct names, so repeating a " +
            "placeholder for emphasis breaks it — and because these are static readonly fields, it " +
            "throws from the type initializer and the application does not start:\n  " +
            string.Join("\n  ", offenders));
    }

    /// <summary>
    /// Yields the type-argument count, the format-string placeholder count, and the
    /// source offset of each <c>LoggerMessage.Define</c> call. The format string is
    /// reassembled from every string literal inside the call — the other arguments
    /// (<c>LogLevel</c>, <c>new EventId(n, nameof(...))</c>) contribute none — so a
    /// message split across concatenated lines is measured whole.
    /// </summary>
    private static IEnumerable<(int TypeArguments, int Placeholders, int Index)> LoggerMessageDefinitions(string source)
    {
        const string call = "LoggerMessage.Define";

        for (var at = source.IndexOf(call, StringComparison.Ordinal);
             at >= 0;
             at = source.IndexOf(call, at + call.Length, StringComparison.Ordinal))
        {
            var cursor = at + call.Length;
            var typeArguments = 0;

            if (cursor < source.Length && source[cursor] == '<')
            {
                var close = MatchingBracket(source, cursor, '<', '>');
                if (close < 0) continue;

                typeArguments = CountTopLevelArguments(source[(cursor + 1)..close]);
                cursor = close + 1;
            }

            while (cursor < source.Length && char.IsWhiteSpace(source[cursor])) cursor++;
            if (cursor >= source.Length || source[cursor] != '(') continue;

            var end = MatchingBracket(source, cursor, '(', ')');
            if (end < 0) continue;

            var arguments = source[(cursor + 1)..end];
            var format = string.Concat(
                Regex.Matches(arguments, @"(?<!@)""(?:[^""\\\n]|\\.)*""")
                    .Select(m => m.Value));

            // {{ is an escaped brace and is not a placeholder.
            var placeholders = Regex.Matches(
                format.Replace("{{", string.Empty, StringComparison.Ordinal),
                @"\{[A-Za-z_][A-Za-z0-9_]*[^}]*\}").Count;

            yield return (typeArguments, placeholders, at);
        }
    }

    private static int MatchingBracket(string source, int open, char opening, char closing)
    {
        var depth = 0;
        for (var i = open; i < source.Length; i++)
        {
            if (source[i] == opening) depth++;
            else if (source[i] == closing && --depth == 0) return i;
        }

        return -1;
    }

    private static int CountTopLevelArguments(string typeArgumentList)
    {
        if (string.IsNullOrWhiteSpace(typeArgumentList)) return 0;

        var count = 1;
        var depth = 0;

        foreach (var character in typeArgumentList)
        {
            if (character is '<' or '(') depth++;
            else if (character is '>' or ')') depth--;
            else if (character == ',' && depth == 0) count++;
        }

        return count;
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Providers_UseLoggerMessageDelegatesRatherThanAdHocLoggerCalls(int providerIndex)
    {
        var relativePath = ProviderPaths[providerIndex];
        var source = ReadRepoFile(relativePath);

        var offenders = AdHocLoggerCall.Matches(source)
            .Select(m => $"{m.Value.TrimEnd('(', ' ')} at offset {m.Index}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"{relativePath} calls ILogger extension methods directly instead of going through a " +
            "LoggerMessage.Define delegate with an allocated EventId. These allocate on every call " +
            "(CA1848) and, more importantly, carry no EventId, so they cannot be filtered or traced:\n  " +
            string.Join("\n  ", offenders));
    }

    /// <summary>Parses the <c>low-high … next: n</c> rows out of the registry comment block.</summary>
    private static List<(int Low, int High, int Next)> DeclaredRanges()
    {
        var registry = ReadRepoFile(RegistryRelativePath);

        var start = registry.IndexOf("EventId allocation across the solution", StringComparison.Ordinal);
        Assert.True(start >= 0, $"Could not find the EventId allocation registry in {RegistryRelativePath}.");

        var end = registry.IndexOf("never reuse or", start, StringComparison.Ordinal);
        Assert.True(end > start, "Could not find the end of the EventId allocation registry comment.");

        var block = registry[start..end];

        // Ranges and their next-free values appear in matching order, but not
        // always on the same line (a long description wraps).
        var lows = Regex.Matches(block, @"(?<low>\d+)-(?<high>\d+)\s").Select(
            m => (Low: int.Parse(m.Groups["low"].Value, System.Globalization.CultureInfo.InvariantCulture),
                  High: int.Parse(m.Groups["high"].Value, System.Globalization.CultureInfo.InvariantCulture))).ToList();

        var nexts = Regex.Matches(block, @"next:\s*(?<next>\d+)").Select(
            m => int.Parse(m.Groups["next"].Value, System.Globalization.CultureInfo.InvariantCulture)).ToList();

        Assert.True(
            lows.Count == nexts.Count,
            $"The registry declares {lows.Count} ranges but {nexts.Count} next-free values; they must pair up.");

        return lows.Zip(nexts, (r, next) => (r.Low, r.High, next)).ToList();
    }

    private static IEnumerable<(string RelativePath, string Source)> SolutionSources()
    {
        var root = Path.Join(RepositoryRoot(), "src");

        foreach (var path in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
                     .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                              && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                     .OrderBy(p => p, StringComparer.Ordinal))
        {
            yield return (Path.GetRelativePath(RepositoryRoot(), path), File.ReadAllText(path));
        }
    }

    private static string ReadRepoFile(string relativePath)
    {
        var path = Path.Join(RepositoryRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(path), $"Expected to find '{relativePath}' at '{path}'.");

        return File.ReadAllText(path);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory != null)
        {
            if (File.Exists(Path.Join(directory.FullName, "Unosquare.PassCore.sln")))
                return directory.FullName;

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "Could not locate the repository root (no Unosquare.PassCore.sln found above " +
            $"'{AppContext.BaseDirectory}'). This audit reads provider source, so it must run from a checkout.");
    }
}
