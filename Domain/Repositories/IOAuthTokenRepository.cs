using System;
using Authentication.Domain.Entities;

namespace Domain.Repositories;

public interface IOAuthTokenRepository
{
    Task AddAsync(OauthToken token);
    Task<OauthToken?> GetByAccessTokenAsync(string accessToken);
    Task<OauthToken?> GetByRefreshTokenAsync(string refreshToken);
    Task SaveChangesAsync();
}
