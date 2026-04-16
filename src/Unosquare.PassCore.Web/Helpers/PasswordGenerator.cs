using SimpleBase;
using System.Security.Cryptography;

namespace Unosquare.PassCore.Web.Helpers;

internal class PasswordGenerator
{
    public string Generate(int entropy)
    {
        var pswBytes = RandomNumberGenerator.GetBytes(entropy);

        var encoder = new Base85(Base85Alphabet.Ascii85);
        return encoder.Encode(pswBytes);
    }
}
