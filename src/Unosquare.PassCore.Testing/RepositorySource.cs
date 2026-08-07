using System;
using System.Collections.Generic;
using System.IO;

namespace Unosquare.PassCore.Testing;

/// <summary>
/// Locates the repository root and reads files from it by relative path. Shared by tests
/// that audit shipped source and configuration, which must run from a source checkout
/// rather than a packaged/published output.
/// </summary>
public static class RepositorySource
{
    /// <summary>
    /// Reads the contents of a file at <paramref name="relativePath"/>, relative to the
    /// repository root.
    /// </summary>
    /// <param name="relativePath">
    /// The path to the file, relative to the repository root. Forward slashes are
    /// normalized to the platform directory separator.
    /// </param>
    /// <returns>The file's contents.</returns>
    public static string ReadRepoFile(string relativePath)
    {
        // Path.Join, not Path.Combine: Join always concatenates, where Combine
        // discards everything before a segment it considers rooted.
        var path = Path.Join(RepositoryRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(path))
            throw new InvalidOperationException($"Expected to find '{relativePath}' at '{path}'.");

        return File.ReadAllText(path);
    }

    /// <summary>
    /// Walks up from <see cref="AppContext.BaseDirectory"/> looking for the directory that
    /// contains Unosquare.PassCore.sln.
    /// </summary>
    /// <returns>The full path of the repository root.</returns>
    public static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        var visited = new List<string>();

        while (directory != null)
        {
            visited.Add(directory.FullName);
            if (File.Exists(Path.Join(directory.FullName, "Unosquare.PassCore.sln")))
                return directory.FullName;

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "Could not locate the repository root (no Unosquare.PassCore.sln found above " +
            $"'{AppContext.BaseDirectory}'). Searched: {string.Join(", ", visited)}. This test " +
            "reads shipped source and configuration, so it must run from a source checkout.");
    }
}
