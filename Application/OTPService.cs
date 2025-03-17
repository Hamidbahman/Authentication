using System.Collections.Concurrent;
using System.Security.Cryptography;
using Application;
using Authentication.Domain.Repositories;
using Kavenegar;
using Microsoft.Extensions.Options;

public class OtpService
{
    private readonly KavenegarApi _api;
    private readonly string _sender;
    private readonly IUserRepository _userRepo; 
    private readonly ConcurrentDictionary<string, OtpInfo> _otpStorage = new();

    public OtpService(IOptions<KavenegarOptions> options, IUserRepository userRepo)
    {
        _api = new KavenegarApi(options.Value.ApiKey);
        _sender = options.Value.Sender;
        _userRepo = userRepo;
    }

    /// <summary>
    /// Generates a secure 6-digit OTP asynchronously.
    /// </summary>
    private async Task<string> GenerateOtpAsync()
    {
        return await Task.Run(() =>
        {
            using var rng = new RNGCryptoServiceProvider ();
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            int value = BitConverter.ToInt32(bytes, 0) & 0x7FFFFFFF;
            return (value % 900000 + 100000).ToString();
        });
    }

    /// <summary>
    /// Sends an OTP via SMS and stores it with the associated phone number.
    /// Validates if the phone number exists in the database before sending OTP.
    /// </summary>
    public async Task<string> SendSmsAsync(string phoneNumber)
    {

        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            throw new ArgumentNullException(nameof(phoneNumber), "Phone number cannot be null or empty.");
        }
        var user = 
        await _userRepo.GetUserByPhoneNumber(phoneNumber);
        if(user == null)
        {
            return "No user with this phone number exists";
        }

        try
        {
            string otpCode = await GenerateOtpAsync();

            var result = await _api.Send(_sender, phoneNumber, otpCode);

            if (result == null)
            {
                throw new Exception("Failed to send SMS, result from API is null.");
            }

            Console.WriteLine($"SMS Sent to {phoneNumber}: MessageId={result.Messageid}");

            var otpInfo = new OtpInfo
            {
                Code = otpCode,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                PhoneNumber = phoneNumber 
            };

            _otpStorage[otpCode] = otpInfo;

            return otpCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in SendSmsAsync: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Validates if the provided OTP code is correct and not expired.
    /// </summary>
    public bool ValidateOtp(string otpCode)
    {
        if (_otpStorage.TryGetValue(otpCode, out var otpInfo))
        {
            if (otpInfo.ExpiresAt < DateTime.UtcNow)
            {
                Console.WriteLine("OTP expired.");
                _otpStorage.TryRemove(otpCode, out _);
                return false;
            }

            return otpInfo.Code == otpCode;
        }

        Console.WriteLine("OTP not found.");
        return false; // OTP not found
    }

    /// <summary>
    /// Retrieves the phone number associated with an OTP code.
    /// </summary>
    public string GetPhoneNumberByOtp(string otpCode)
    {
        if (_otpStorage.TryGetValue(otpCode, out var otpInfo))
        {
            return otpInfo.PhoneNumber; 
        }
        return null; 
    }

    /// <summary>
    /// Represents OTP information including the associated phone number.
    /// </summary>
    private class OtpInfo
    {
        public string Code { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string PhoneNumber { get; set; } 
    }
}
