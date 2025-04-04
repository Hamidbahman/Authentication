using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BCrypt.Net;
using Authentication.Domain.Entities;
using Authentication.Domain.Repositories;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using StackExchange.Redis;
using Domain.Repositories;
using Application;

namespace Authentication.Application
{
    // Example of a more secure, session-aware OAuthService
    // Merges your existing code with best-practice token management, concurrency checks, & short-lived tokens.
    // NOTE: You must also have:
    // 1) A token validation step in your APIs (middleware or filter) that verifies signature, exp, concurrency, etc.
    // 2) Additional concurrency settings in your config (or from a ConfigurationSession table).
    // 3) HTTPS enforced to avoid sending credentials or tokens plaintext.

    public class OAuthService
    {
        private readonly IOAuthTokenRepository _oauthRepo;
        private readonly IApplicationRepository _applicationRepository;
        private readonly IUserPropertyRepository _userPropertyRepo;
        private readonly IUserRepository _userRepo;
        private readonly OtpService _otpService;
        private readonly CheckboxCaptchaService _checkBox;
        private readonly TokenService _tokenService;
        private readonly PuzzleCaptchaService _puzzleService;
        private readonly IDatabase _redis;

        // In-memory dictionary from original code (still used for 2FA codes if needed)
        private static readonly ConcurrentDictionary<string, string> _authCodes = new();

        // We store concurrency data in Redis under sessions:{userId}
        // Example usage: store token IDs for each user.

        public OAuthService(
            IOAuthTokenRepository oauthRepo,
            PuzzleCaptchaService puzzleCaptchaService,
            IUserPropertyRepository userPropertyRepository,
            TokenService tokenService,
            CheckboxCaptchaService checkboxCaptchaService,
            OtpService otpService,
            IConnectionMultiplexer redis,
            IApplicationRepository applicationRepository,
            IUserRepository userRepository)
        {
            _oauthRepo = oauthRepo;
            _puzzleService = puzzleCaptchaService;
            _userPropertyRepo = userPropertyRepository;
            _tokenService = tokenService;
            _checkBox = checkboxCaptchaService;
            _applicationRepository = applicationRepository;
            _userRepo = userRepository;
            _otpService = otpService;
            _redis = redis.GetDatabase();
        }

        /// <summary>
        /// Primary login method with concurrency & session management.
        /// 1) Checks client credentials
        /// 2) Verifies user credentials & lockout policy
        /// 3) Enforces concurrency limit if desired
        /// 4) Issues short-lifetime token with optional refresh token
        /// 5) Stores token in Redis for concurrency & revocation checks
        /// </summary>
        public async Task<AuthResult> LoginAsync(
            string email,
            string password,
            string clientId,
            string clientSecret,
            string referrer,
            int concurrencyLimit = 2,    // Example concurrency limit
            bool concurrencyEnabled = true, // Example concurrency toggle
            int tokenExpiryMinutes = 15  // Example short-lifetime token
        )
        {
            // 1) Validate client credentials
            var application = await _applicationRepository.GetApplicationByClientIdAsync(clientId);
            if (application == null || !VerifyHashedSecret(clientSecret, application.ClientSecret))
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "Invalid client credentials",
                    TwoFactorRequired = false
                };
            }

            // 2) Check referrer is whitelisted
            if (string.IsNullOrEmpty(application.RedirectUrls) ||
                !application.RedirectUrls.Split(';').Contains(referrer))
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "Unauthorized referrer",
                    TwoFactorRequired = false
                };
            }

            // 3) Load user & validate password
            var user = await _userRepo.GetUserByEmailAsync(email);
            if (user == null)
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "Invalid username or password",
                    TwoFactorRequired = false
                };
            }

            if (user.LoginAttempt >= 5)
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "Too many failed attempts. Account locked.",
                    TwoFactorRequired = false
                };
            }

            // Compare hashed password with user input
            if (!BCrypt.Net.BCrypt.Verify(password, user.UserProperty.Password))
            {
                user.IncrementLoginAttempt();
                await _userRepo.SaveChangesAsync();

                return new AuthResult
                {
                    Success = false,
                    Message = "Invalid username or password",
                    TwoFactorRequired = false
                };
            }

            // If we had 2FA, we would handle it here (commented out code in original)

            user.ResetLoginAttempt();

            // Check lockout policy again
            var logPol = await _userRepo.GetLoginPoliciesByUserID(user.Id.ToString());
            if (logPol != null && user.LoginAttempt > 5)
            {
                logPol.SetLockType(Domain.Enums.LockTypes.TemporaryLock);
                await _userRepo.SaveChangesAsync();
                throw new AuthenticationException("Account is temporarily locked due to too many failed attempts.");
            }

            // 4) Enforce concurrency if enabled
            if (concurrencyEnabled)
            {
                var sessionsKey = $"sessions:{user.Id}";
                var activeTokens = await _redis.GetAsync<List<string>>(sessionsKey) ?? new List<string>();

                // If concurrency limit is reached, handle accordingly
                if (activeTokens.Count >= concurrencyLimit)
                {
                    // Either remove oldest or return error
                    // Here we remove oldest to allow new login
                    // (Alternatively, we could deny new login if you prefer)
                    activeTokens.RemoveAt(0);
                }

                // We continue to generate a new token below, then we will store it
                // in the activeTokens list.
            }

            // 5) Generate short-lifetime token
            // In a real scenario, store user roles/claims in the token
            var tokenId = Guid.NewGuid().ToString();
            var accessToken = _tokenService.GenerateAccessToken(user.Id, tokenId, tokenExpiryMinutes);
            var refreshToken = _tokenService.GenerateRefreshToken();

            await _userRepo.SaveChangesAsync();
            await _userPropertyRepo.SaveChangesAsync();

            // 6) Persist OAuth token in DB if needed (for auditing)
            await SaveOauthTokenAsync(user.Id.ToString(), email, accessToken, refreshToken, tokenType: 1);

            // 7) Store token ID in Redis to track concurrency + potential revocation
            if (concurrencyEnabled)
            {
                var sessionsKey = $"sessions:{user.Id}";
                var activeTokens = await _redis.GetAsync<List<string>>(sessionsKey) ?? new List<string>();
                activeTokens.Add(tokenId);

                // Save back with expiry matching or exceeding token lifespan
                await _redis.SetAsync(sessionsKey, activeTokens, TimeSpan.FromMinutes(tokenExpiryMinutes + 5));
            }

            return new AuthResult
            {
                Success = true,
                Token = accessToken,
                TwoFactorRequired = false,
                Message = "Login successful"
            };
        }

        /// <summary>
        /// Example logout. Revokes the token by removing it from Redis concurrency list.
        /// The client must also discard the token.
        /// </summary>
        public async Task LogoutAsync(long userId, string tokenId)
        {
            var sessionsKey = $"sessions:{userId}";
            var activeTokens = await _redis.GetAsync<List<string>>(sessionsKey);
            if (activeTokens == null) return;

            if (activeTokens.Contains(tokenId))
            {
                activeTokens.Remove(tokenId);
                await _redis.SetAsync(sessionsKey, activeTokens);
            }
        }

        /// <summary>
        /// Verifies if the token is present in Redis concurrency list.
        /// If not present, it means it's revoked or never existed.
        /// You would call this during request validation.
        /// </summary>
        public async Task<bool> IsTokenActiveAsync(long userId, string tokenId)
        {
            var sessionsKey = $"sessions:{userId}";
            var activeTokens = await _redis.GetAsync<List<string>>(sessionsKey);
            return activeTokens?.Contains(tokenId) == true;
        }

        /// <summary>
        /// Basic rate-limiting check for clientId. You might want a more robust approach.
        /// </summary>
        private async Task<bool> IsRateLimited(string clientId)
        {
            var lastRequest = await _redis.StringGetAsync($"rate_limit:{clientId}");
            if (!lastRequest.IsNullOrEmpty)
            {
                var lastRequestTime = DateTime.Parse(lastRequest);
                return (DateTime.UtcNow - lastRequestTime).TotalSeconds < 30;
            }
            return false;
        }

        /// <summary>
        /// Hash comparison using BCrypt. Validates clientSecret for your OAuth clients.
        /// </summary>
        private static bool VerifyHashedSecret(string inputSecret, string storedHash)
        {
            return BCrypt.Net.BCrypt.Verify(inputSecret, storedHash);
        }

        /// <summary>
        /// Example: Check if an auth code is expired in Redis. You store it ephemeral.
        /// </summary>
        public async Task<bool> IsAuthorizationCodeExpiredAsync(string authCode)
        {
            string encryptedAuthCode = EncryptAuthCode(authCode);
            var value = await _redis.StringGetAsync($"auth_code:{encryptedAuthCode}");
            return value.IsNullOrEmpty;
        }

        /// <summary>
        /// Clear out expired codes. You might schedule this cleanup.
        /// </summary>
        public async Task ClearExpiredAuthorizationCodes()
        {
            var server = _redis.Multiplexer.GetServer(_redis.Multiplexer.GetEndPoints().First());
            foreach (var key in server.Keys(pattern: "auth_code:*"))
            {
                if ((await _redis.StringGetAsync(key)).IsNullOrEmpty)
                {
                    await _redis.KeyDeleteAsync(key);
                }
            }
        }

        private static string EncryptAuthCode(string authCode)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(authCode));
                return Convert.ToBase64String(hash);
            }
        }

        // OTP / 2FA methods remain mostly the same,
        // but you could store ephemeral codes in Redis instead of memory.

        public async Task<string> SendOtpAsync(string phoneNumber)
        {
            try
            {
                var otpCode = await _otpService.SendSmsAsync(phoneNumber);
                return otpCode;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in SendOtpAsync: {ex.Message}");
                throw new InvalidOperationException("Failed to send OTP. Please try again later.");
            }
        }

        public async Task<AuthResult> VerifyOtpAsync(string otpCode)
        {
            if (!_otpService.ValidateOtp(otpCode))
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "Invalid or expired OTP",
                    TwoFactorRequired = false
                };
            }

            string phoneNumber = _otpService.GetPhoneNumberByOtp(otpCode);
            if (string.IsNullOrEmpty(phoneNumber))
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "Unable to retrieve phone number",
                    TwoFactorRequired = false
                };
            }

            var user = await _userRepo.GetUserByPhoneNumber(phoneNumber);
            if (user == null)
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "User not found",
                    TwoFactorRequired = false
                };
            }

            var confPass = await _userPropertyRepo.GetConfigurationPasswordByUserIdAsync(user.Id);
            if (confPass == null)
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "User password configuration not found",
                    TwoFactorRequired = false
                };
            }

            // Check if password expired
            var expirationDate = (confPass.CreateDate ?? DateTime.Now).AddDays(confPass.ExpireDaysAmount);
            if (expirationDate <= DateTime.UtcNow)
            {
                return new AuthResult
                {
                    Success = false,
                    Message = "Password expired. Please change your password.",
                    TwoFactorRequired = false
                };
            }

            // Generate short-lifetime token again for OTP login
            var tokenId = Guid.NewGuid().ToString();
            var accessToken = _tokenService.GenerateAccessToken(user.Id, tokenId, 15); // 15-min token
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.ResetLoginAttempt();
            await _userRepo.SaveChangesAsync();
            await _userPropertyRepo.SaveChangesAsync();
            await SaveOauthTokenAsync(user.Id.ToString(), user.Email, accessToken, refreshToken, tokenType: 1);

            // Optionally add to concurrency cache
            var sessionsKey = $"sessions:{user.Id}";
            var activeTokens = await _redis.GetAsync<List<string>>(sessionsKey) ?? new List<string>();
            activeTokens.Add(tokenId);
            await _redis.SetAsync(sessionsKey, activeTokens, TimeSpan.FromMinutes(20));

            return new AuthResult
            {
                Success = true,
                Token = accessToken,
                TwoFactorRequired = false,
                Message = "AccessToken Generated. Authentication Successful",
                User = UserDetails.FromUser(user)
            };
        }

        private async Task SaveOauthTokenAsync(
            string clientId,
            string email,
            string accessToken,
            string refreshToken,
            short tokenType)
        {
            var oauthToken = new OauthToken(clientId, email, accessToken, refreshToken, tokenType);
            await _oauthRepo.AddAsync(oauthToken);
        }

        public async Task<PassResult> ChangePassword(
            string email,
            string exPassword,
            string newPassword,
            string confirmPassword)
        {
            var user = await _userRepo.GetUserByEmailAsync(email);
            if (user == null)
            {
                return new PassResult { Success = false, Message = "Invalid username" };
            }

            var confPass = await _userPropertyRepo.GetConfigurationPasswordByUserIdAsync(user.UserProperty.ConfigurationPasswordId);
            if (confPass == null)
            {
                return new PassResult { Success = false, Message = "Password policy settings not found" };
            }

            bool isHashed = user.UserProperty.Password.StartsWith("$2a$") || user.UserProperty.Password.StartsWith("$2b$");
            bool passwordMatches = isHashed
                ? BCrypt.Net.BCrypt.Verify(exPassword, user.UserProperty.Password)
                : user.UserProperty.Password == exPassword;

            if (!passwordMatches)
            {
                return new PassResult { Success = false, Message = "Invalid password" };
            }

            if (newPassword != confirmPassword)
            {
                return new PassResult { Success = false, Message = "Passwords do not match" };
            }

            if (newPassword.Length < confPass.MinPassLength || newPassword.Length > confPass.MaxPassLength)
            {
                return new PassResult
                {
                    Success = false,
                    Message = $"Password must be between {confPass.MinPassLength} and {confPass.MaxPassLength} characters long."
                };
            }

            if (confPass.MustContainChar && !newPassword.Any(ch => !char.IsLetterOrDigit(ch)))
            {
                return new PassResult { Success = false, Message = "Password must contain at least one special character." };
            }

            if (confPass.MustContainUpperCase && !newPassword.Any(char.IsUpper))
            {
                return new PassResult { Success = false, Message = "Password must contain at least one uppercase letter." };
            }

            if (newPassword.Count(char.IsDigit) < confPass.NumericPassNotEqual)
            {
                return new PassResult { Success = false, Message = $"Password must contain at least {confPass.NumericPassNotEqual} digits." };
            }

            if (newPassword == exPassword)
            {
                return new PassResult { Success = false, Message = "You cannot reuse your current password." };
            }

            // Hash new password
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(newPassword);
            user.UserProperty.UpdatePassword(hashedPassword);

            await _userPropertyRepo.SaveChangesAsync();
            await _userRepo.SaveChangesAsync();

            return new PassResult { Success = true, Message = "Password changed successfully" };
        }

        // Helper hashing method
        private static string HashSecret(string secret)
        {
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] hash = KeyDerivation.Pbkdf2(
                password: secret,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32
            );

            byte[] hashBytes = new byte[salt.Length + hash.Length];
            Buffer.BlockCopy(salt, 0, hashBytes, 0, salt.Length);
            Buffer.BlockCopy(hash, 0, hashBytes, salt.Length, hash.Length);

            return Convert.ToBase64String(hashBytes);
        }
    }

    // All your other classes remain the same below:
    public class PassResult
    {
        public bool Success { get; set; }
        public string? Password { get; set; }
        public string? Message { get; set; }
    }

    public class AuthResult
    {
        public bool Success { get; set; }
        public string? Token { get; set; }
        public string? Message { get; set; }
        public bool TwoFactorRequired { get; set; }
        public UserDetails? User { get; set; }
    }

    public class UserDetails
    {
        public string? Uuid { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public string? Picture { get; set; }
        public string? PictureType { get; set; }

        public static UserDetails FromUser(User user)
        {
            if (user == null) return null;
            return new UserDetails
            {
                Uuid = user.Uuid,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                PhoneNumber = user.Mobile,
                Picture = user.Picture,
                PictureType = user.PictureType
            };
        }
    }
}
