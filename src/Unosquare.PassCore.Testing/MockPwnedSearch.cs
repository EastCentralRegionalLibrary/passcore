using System.Collections.Generic;
using System.Threading.Tasks;
using PwnedPasswordsSearch;

namespace Unosquare.PassCore.Testing;

/// <summary>
/// A mock implementation of IPwnedPasswordSearch for testing purposes.
/// </summary>
public class MockPwnedSearch : IPwnedPasswordSearch
{
    private readonly HashSet<string> _pwnedPasswords = new();

    /// <summary>
    /// Adds a password to the list of pwned passwords.
    /// </summary>
    /// <param name="password">The password to mark as pwned.</param>
    public void AddPwnedPassword(string password) => _pwnedPasswords.Add(password);

    /// <inheritdoc />
    public Task<bool> IsPwnedPasswordAsync(string plaintext) => Task.FromResult(_pwnedPasswords.Contains(plaintext));
}
