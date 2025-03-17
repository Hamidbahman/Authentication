using System;

namespace Authentication.Application;

public interface IOauthService

{
    Task<string?> ValidateClientAsync(string clientId, string clientSecret);
    Task<string?> GenerateAuthorizationCodeAsync(string clientId);
    Task<(string accessToken, string refreshToken)?> ExchangeAuthorizationCodeAsync(string authorizationCode, string username, string password);
    Task<string?> RefreshAccessTokenAsync(string refreshToken);
}


