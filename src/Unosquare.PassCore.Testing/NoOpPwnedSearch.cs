using System.Threading.Tasks;
using PwnedPasswordsSearch;

namespace Unosquare.PassCore.Testing;

/// <summary>
/// A no-op implementation of IPwnedPasswordSearch that always returns false.
/// </summary>
public class NoOpPwnedSearch : IPwnedPasswordSearch
{
    /// <inheritdoc />
    public Task<bool> IsPwnedPasswordAsync(string plaintext) => Task.FromResult(false);
}
