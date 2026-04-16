using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace PwnedPasswordsSearch
{
    public interface IPwnedPasswordSearch
    {
        Task<bool> IsPwnedPasswordAsync(string plaintext, ILogger? logger = null);
    }
}
