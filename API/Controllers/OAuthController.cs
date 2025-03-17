using Authentication.Application;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace Authentication.Application
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly OAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(OAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }
        [HttpPost("token")]
        public async Task<IActionResult> GenerateToken([FromBody] TokenRequestModel model)
        {
            var clientId = Request.Headers["Client-Id"].ToString();
            var clientSecret = Request.Headers["Client-Secret"].ToString();
            var referrer = Request.Headers["Referer"].ToString();

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                return BadRequest(new { error = "Client credentials are required." });
            }

            var authResult = await _authService.LoginAsync(model.Email, model.Password, clientId, clientSecret, referrer);

            if (!authResult.Success)
            {
                return Unauthorized(new { error = authResult.Message });
            }

            return Ok(new
            {
                access_token = authResult.Token,
                two_factor_required = authResult.TwoFactorRequired
            });
        }










        [HttpPost("send-otp")]
        public async Task<IActionResult> SendOtp([FromBody] SendOtpRequest request)
        {
            try
            {
                await _authService.SendOtpAsync(request.PhoneNumber);
                return Ok(new { Message = "OTP sent successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending OTP.");
                return BadRequest(new { Message = "Failed to send OTP. Please try again later.", Error = ex.Message });
            }
        }

        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] OtpRequest request)
        {
            var result = await _authService.VerifyOtpAsync(request.OtpCode);
            if (result.Success) return Ok(new { Token = result.Token });

            return Unauthorized(new { Message = result.Message });
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest model)
        {
            if (model == null)
                return BadRequest(new { Message = "Invalid request." });

            try
            {
                var result = await _authService.ChangePassword(model.Email, model.ExPassword, model.NewPassword, model.ConfirmPassword);

                if (!result.Success)
                    return BadRequest(new { Message = result.Message });

                return Ok(new { Message = result.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password.");
                return StatusCode(500, new { Message = "An error occurred.", Error = ex.Message });
            }
        }
    }

    public class ChangePasswordRequest
    {
        public string Email { get; set; }
        public string ExPassword { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }
    }

    public class AuthCodeRequest
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string? UserCaptchaToken { get; set; }
    }


    public class TokenRequestModel
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class OtpRequest
    {
        public string OtpCode { get; set; } = string.Empty;
    }

    public class SendOtpRequest
    {
        public string PhoneNumber { get; set; } = string.Empty;
    }
}




