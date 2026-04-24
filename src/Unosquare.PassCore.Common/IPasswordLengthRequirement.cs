using System.Threading.Tasks;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Defines a provider that can report its own minimum password length requirement.
/// </summary>
public interface IPasswordLengthRequirement
{
    /// <summary>
    /// Gets the minimum password length requirement.
    /// </summary>
    /// <returns>A task representing the asynchronous operation, containing the minimum length.</returns>
    Task<int> GetMinimumLengthAsync();
}
