using System;
using System.Threading.Tasks;
using Authenitcation.Infrastructure.Data;
using Authentication.Domain.Entities;
using Authentication.Domain.Repositories;
using Domain.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Infrastructure.Repositories
{
    public class OauthTokenRepository : IOAuthTokenRepository
    {
        private readonly AutheDbContext _context;

        public OauthTokenRepository(AutheDbContext context)
        {
            _context = context;
        }
    
        public async Task AddAsync(OauthToken token)
        {
            await _context.OauthTokens.AddAsync(token); // First, add the entity
            await _context.SaveChangesAsync(); // Then save changes
        }

        public async Task<OauthToken?> GetByAccessTokenAsync(string accessToken)
        {
            return await _context.OauthTokens
                .FirstOrDefaultAsync(t => t.AccessToken == accessToken);
        }

        public async Task<OauthToken?> GetByRefreshTokenAsync(string refreshToken)
        {
            return await _context.OauthTokens
                .FirstOrDefaultAsync(t => t.RefreshToken == refreshToken);
        }

        public async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
