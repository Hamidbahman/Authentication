using System;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using System.Text.Json;

namespace Application;

public class TokenService
{
    private readonly byte[] _secretKey;
    private const int ACCESS_TOKEN_EXPIRATION_MINUTES = 30;
    private const int REFRESH_TOKEN_EXPIRATION_DAYS = 7;

    public class TokenValidationResult
    {
        public bool IsValid { get; set; }
        public long? UserId { get; set; }
        public DateTime? IssuedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
    }

    public TokenService(IConfiguration configuration)
    {
        var secretKeyString = configuration["AccessToken:SecretKey"] 
            ?? throw new InvalidOperationException("Secret key is missing");
        
        // Ensure secret key is at least 32 bytes (256 bits)
        _secretKey = DeriveKey(secretKeyString);
    }

    private byte[] DeriveKey(string input)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(
            Encoding.UTF8.GetBytes(input), 
            Encoding.UTF8.GetBytes("TokenServiceSalt"), 
            iterations: 10000, 
            HashAlgorithmName.SHA256
        );
        return pbkdf2.GetBytes(32);
    }

    public string GenerateAccessToken(long userId)
    {
        var claims = new Dictionary<string, string>
        {
            ["userId"] = userId.ToString(),
            ["issued"] = DateTime.UtcNow.Ticks.ToString(),
            ["expiration"] = DateTime.UtcNow.AddMinutes(ACCESS_TOKEN_EXPIRATION_MINUTES).Ticks.ToString(),
            ["jti"] = Guid.NewGuid().ToString()
        };

        string claimsJson = JsonSerializer.Serialize(claims);
        byte[] claimsBytes = Encoding.UTF8.GetBytes(claimsJson);

        using var hmac = new HMACSHA512(_secretKey);
        byte[] signature = hmac.ComputeHash(claimsBytes);

        string encodedClaims = Convert.ToBase64String(claimsBytes);
        string encodedSignature = Convert.ToBase64String(signature);

        return $"{encodedClaims}.{encodedSignature}";
    }

    public string GenerateRefreshToken()
    {
        byte[] randomBytes = new byte[64]; 
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        using var hmac = new HMACSHA512(_secretKey);
        byte[] hashedBytes = hmac.ComputeHash(randomBytes);

        return Convert.ToBase64String(hashedBytes);
    }

    public TokenValidationResult ValidateAccessToken(string token)
    {
        try 
        {
            var parts = token.Split('.');
            if (parts.Length != 2)
                return new TokenValidationResult { IsValid = false };

            byte[] claimsBytes = Convert.FromBase64String(parts[0]);
            byte[] providedSignature = Convert.FromBase64String(parts[1]);

            // Verify signature
            using var hmac = new HMACSHA512(_secretKey);
            byte[] computedSignature = hmac.ComputeHash(claimsBytes);

            if (!SecurityHelper.SecureCompare(computedSignature, providedSignature))
                return new TokenValidationResult { IsValid = false };

            var claims = JsonSerializer.Deserialize<Dictionary<string, string>>(
                Encoding.UTF8.GetString(claimsBytes)
            );

            long userId = long.Parse(claims["userId"]);
            long issuedTicks = long.Parse(claims["issued"]);
            long expirationTicks = long.Parse(claims["expiration"]);

            var issuedAt = new DateTime(issuedTicks);
            var expiresAt = new DateTime(expirationTicks);

            if (DateTime.UtcNow > expiresAt)
                return new TokenValidationResult { IsValid = false };

            return new TokenValidationResult 
            { 
                IsValid = true, 
                UserId = userId,
                IssuedAt = issuedAt,
                ExpiresAt = expiresAt
            };
        }
        catch
        {
            return new TokenValidationResult { IsValid = false };
        }
    }

    private static class SecurityHelper
    {
        public static bool SecureCompare(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            uint diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }
    }
}