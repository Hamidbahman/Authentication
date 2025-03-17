
using System;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Application;

public class TokenValidationService
{
    private readonly string _secretKey;
    private readonly TimeSpan _tokenLifetime = TimeSpan.FromHours(1); // Token expires in 1 hour

    public TokenValidationService(IConfiguration configuration)
    {
        _secretKey = configuration["AppSettings:SecretKey"]
                     ?? throw new InvalidOperationException("Secret key is missing in configuration.");
    }

    public bool ValidateToken(string token, out long userId)
    {
        userId = 0;
        if (string.IsNullOrWhiteSpace(token) || !token.Contains(":"))
            return false;

        string[] parts = token.Split(':');
        if (parts.Length < 4)
            return false;

        if (!long.TryParse(parts[0], out userId))
            return false;

        if (!long.TryParse(parts[2], out long timestamp))
            return false;

        // Convert timestamp back to DateTime
        DateTime tokenTime = new DateTime(timestamp, DateTimeKind.Utc);
        if (DateTime.UtcNow - tokenTime > _tokenLifetime)
            return false; // Token has expired

        string tokenData = $"{parts[0]}:{parts[1]}:{parts[2]}"; // User ID, GUID, Timestamp
        string receivedSignature = parts[3];

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_secretKey));
        byte[] tokenBytes = Encoding.UTF8.GetBytes(tokenData);
        byte[] hash = hmac.ComputeHash(tokenBytes);
        string expectedSignature = Convert.ToBase64String(hash);

        return expectedSignature == receivedSignature;
    }
}

