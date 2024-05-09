using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

public static class PasswordHasher
{
    private const int IterationCount = 10000;
    private const int HashSize = 32;     
    private static readonly byte[] StaticSalt = Convert.FromBase64String("ZmFrZVN0YXRpY1NhbHQ=");

    public static string HashPassword(string password)
    {
        byte[] salt = StaticSalt;

        byte[] hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: IterationCount,
            numBytesRequested: HashSize
        );

        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }
}