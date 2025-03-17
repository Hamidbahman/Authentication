
using Authenitcation.Infrastructure.Data;
using Authentication.Domain.Entities;
using Authentication.Domain.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Authenitcation.Infrastructure.Repositories;


    public class ApplicationRepository : IApplicationRepository
    {
        private readonly AutheDbContext _context;

        public ApplicationRepository(AutheDbContext context)
        {
            _context = context;
        }


    public async Task<Application?> GetApplicationByClientIdAsync(string clientId)
    {
        return await _context.Applications
            .FirstOrDefaultAsync(a => a.ClientId == clientId);        
    }


    public async Task<ConfigurationLock?> GetConfigurationLockAsync(string clientId)
    {
        return await _context.Applications
        .Where(app => app.ClientId == clientId)
        .SelectMany(app => app.ConfigurationLocks) 
        .OrderByDescending(cl => cl.Id) 
        .FirstOrDefaultAsync();
    }

    public async Task<ConfigurationPassword?> GetConfigurationPasswordAsync(string clientId)
    {
        return await _context.Applications
        .Where(app => app.ClientId == clientId)
        .Select(app => app.ConfigurationPassword) 
        .OrderByDescending(cl => cl.Id) 
        .FirstOrDefaultAsync();
    }

    public async Task<bool> SaveChangesAsync()
    {
        await _context.SaveChangesAsync();
        return true;
    }
}

