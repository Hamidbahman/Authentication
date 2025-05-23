using System;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using System.Text.Json;
using System.Web;
using System.Collections.Generic;

namespace Application
{
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
            public string? Issuer { get; set; }
            public string? Audience { get; set; }
        }

        public TokenService(IConfiguration configuration)
        {
            var secretKeyString = configuration["AccessToken:SecretKey"] 
                ?? throw new InvalidOperationException("Secret key is missing");
            
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

        /// <summary>
        /// Generates an access token containing:
        /// - userId
        /// - iat (issued time, UTC ticks)
        /// - exp (expiration time, UTC ticks)
        /// - jti (unique token ID)
        /// - iss (issuer)
        /// - aud (audience)
        /// Signed using HMACSHA512 over the base64url-encoded payload.
        /// </summary>
        public string GenerateAccessToken(
            long userId,
            string? issuer = null,
            string? audience = null,
            int? tokenExpiryMinutes = null
        )
        {
            var now = DateTime.UtcNow;
            var expirationMinutes = tokenExpiryMinutes ?? ACCESS_TOKEN_EXPIRATION_MINUTES;

            var claims = new Dictionary<string, string>
            {
                ["userId"] = userId.ToString(),
                ["iat"] = now.Ticks.ToString(),
                ["exp"] = now.AddMinutes(expirationMinutes).Ticks.ToString(),
                ["jti"] = Guid.NewGuid().ToString(),
            };

            if (!string.IsNullOrEmpty(issuer))
                claims["iss"] = issuer;

            if (!string.IsNullOrEmpty(audience))
                claims["aud"] = audience;

            string claimsJson = JsonSerializer.Serialize(claims);
            byte[] claimsBytes = Encoding.UTF8.GetBytes(claimsJson);

            using var hmac = new HMACSHA512(_secretKey);
            byte[] signature = hmac.ComputeHash(claimsBytes);

            string encodedClaims = Base64UrlEncode(claimsBytes);
            string encodedSignature = Base64UrlEncode(signature);

            return $"{encodedClaims}.{encodedSignature}";
        }

        /// <summary>
        /// Generates a random refresh token hashed with the service key.
        /// You typically store this hashed token string in your database 
        /// (along with user ID, expiration, etc.).
        /// </summary>
        public string GenerateRefreshToken()
        {
            byte[] randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            using var hmac = new HMACSHA512(_secretKey);
            byte[] hashedBytes = hmac.ComputeHash(randomBytes);

            return Base64UrlEncode(hashedBytes);
        }

        /// <summary>
        /// Validates the refresh token by comparing the provided token 
        /// (from the client) with the stored hashed token (from the DB).
        /// </summary>
        public bool ValidateRefreshToken(string providedRefreshToken, string storedHashedRefreshToken)
        {
            if (string.IsNullOrEmpty(providedRefreshToken) || string.IsNullOrEmpty(storedHashedRefreshToken))
                return false;

            byte[] providedBytes = Base64UrlDecode(providedRefreshToken);
            byte[] storedBytes = Base64UrlDecode(storedHashedRefreshToken);

            // Compare in a timing-safe manner
            return SecureCompare(providedBytes, storedBytes);
        }

        /// <summary>
        /// Validates the custom access token by:
        /// 1) Splitting claims + signature
        /// 2) Recomputing signature with HMACSHA512
        /// 3) Checking token expiration
        /// 4) Returning claims if valid
        /// </summary>
        public TokenValidationResult ValidateAccessToken(string token)
        {
            try
            {
                var parts = token.Split('.');
                if (parts.Length != 2)
                    return new TokenValidationResult { IsValid = false };

                byte[] claimsBytes = Base64UrlDecode(parts[0]);
                byte[] providedSignature = Base64UrlDecode(parts[1]);

                using var hmac = new HMACSHA512(_secretKey);
                byte[] computedSignature = hmac.ComputeHash(claimsBytes);

                if (!SecureCompare(computedSignature, providedSignature))
                    return new TokenValidationResult { IsValid = false };

                var claims = JsonSerializer.Deserialize<Dictionary<string, string>>(
                    Encoding.UTF8.GetString(claimsBytes)
                );

                if (claims == null) 
                    return new TokenValidationResult { IsValid = false };

                if (!claims.TryGetValue("userId", out var userIdStr)
                    || !claims.TryGetValue("iat", out var issuedStr)
                    || !claims.TryGetValue("exp", out var expStr))
                {
                    return new TokenValidationResult { IsValid = false };
                }

                long userId = long.Parse(userIdStr);
                long issuedTicks = long.Parse(issuedStr);
                long expirationTicks = long.Parse(expStr);

                var issuedAt = new DateTime(issuedTicks, DateTimeKind.Utc);
                var expiresAt = new DateTime(expirationTicks, DateTimeKind.Utc);

                if (DateTime.UtcNow > expiresAt)
                    return new TokenValidationResult { IsValid = false };

                var result = new TokenValidationResult
                {
                    IsValid = true,
                    UserId = userId,
                    IssuedAt = issuedAt,
                    ExpiresAt = expiresAt
                };

                if (claims.TryGetValue("iss", out var iss))
                    result.Issuer = iss;

                if (claims.TryGetValue("aud", out var aud))
                    result.Audience = aud;

                return result;
            }
            catch
            {
                return new TokenValidationResult { IsValid = false };
            }
        }

        // ===== Helpers =====

        /// <summary>
        /// Base64Url encoding (RFC 4648) – avoids +, /, and = characters to be URL-safe.
        /// </summary>
        private static string Base64UrlEncode(byte[] input)
        {
            var base64 = Convert.ToBase64String(input)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
            return base64;
        }

        /// <summary>
        /// Base64Url decoding to revert back to the original bytes.
        /// </summary>
        private static byte[] Base64UrlDecode(string input)
        {
            string output = input
                .Replace('-', '+')
                .Replace('_', '/');
            switch (output.Length % 4)
            {
                case 2: output += "=="; break;
                case 3: output += "="; break;
            }
            return Convert.FromBase64String(output);
        }

        /// <summary>
        /// Timing-safe comparison to avoid side-channel attacks.
        /// </summary>
        private static bool SecureCompare(byte[] a, byte[] b)
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
