using System.Threading.Tasks;

namespace PwnedPasswordsSearch
{
    /// <summary>
    /// Service interface for looking up pwned passwords.
    /// </summary>
    public interface IPwnedPasswordSearch
    {
        /// <summary>
        /// Checks if the given plaintext password is in the pwned list.
        /// </summary>
        /// <param name="plaintext">The password to verify.</param>
        /// <returns>True if the password has been leaked; otherwise, false.</returns>
        Task<bool> IsPwnedPasswordAsync(string plaintext);
    }
}
