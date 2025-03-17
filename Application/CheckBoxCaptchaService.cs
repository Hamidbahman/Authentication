using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace Authentication.Application;

public class CheckboxCaptchaService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CheckboxCaptchaService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public string GenerateCaptchaToken()
    {
        var token = Guid.NewGuid().ToString();

        var context = _httpContextAccessor.HttpContext;
        if (context != null && context.Session != null)
        {
            context.Session.SetString("CaptchaToken", token);
        }

        return token;
    }

    public bool ValidateCaptchaToken(string userToken)
    {
        var context = _httpContextAccessor.HttpContext;
        if (context != null && context.Session != null)
        {
            var storedToken = context.Session.GetString("CaptchaToken");
            return storedToken != null && storedToken == userToken;
        }

        return false;
    }
}
