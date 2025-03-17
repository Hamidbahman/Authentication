using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace Authentication.Application;

public class RecaptchaService
{
    private readonly HttpClient _httpClient;
    private readonly string _recaptchaSecretKey; 

    public RecaptchaService(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _recaptchaSecretKey = configuration["Recaptcha:SecretKey"] ?? throw new ArgumentNullException("Recaptcha secret key is missing.");
    }

    public async Task<bool> ValidateRecaptchaAsync(string recaptchaResponse)
    {
        try
        {
            var requestData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("secret", _recaptchaSecretKey),
                new KeyValuePair<string, string>("response", recaptchaResponse)
            });

            var response = await _httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", requestData);
            if (!response.IsSuccessStatusCode)
                return false;

            var responseContent = await response.Content.ReadAsStringAsync();
            using var jsonDoc = JsonDocument.Parse(responseContent);

            return jsonDoc.RootElement.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"reCAPTCHA validation error: {ex.Message}");
            return false; 
        }
    }
}
