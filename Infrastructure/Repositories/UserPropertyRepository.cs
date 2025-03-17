using System;
using Authenitcation.Infrastructure.Data;
using Authentication.Domain.Entities;
using Domain.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories;

public class UserPropertyRepository : IUserPropertyRepository
{
    private readonly AutheDbContext _context;
    public UserPropertyRepository(AutheDbContext context)
    {
        _context = context;
    }

    public async Task<ConfigurationPassword?> GetConfigurationPasswordByUserIdAsync(long configurationPasswordId)
    {

        return await _context.UserProperties
            .Where(up => up.ConfigurationPasswordId == configurationPasswordId) 
            .Select(up => up.ConfigurationPassword)
            .FirstOrDefaultAsync(); 
    }

    public async Task<bool> SaveChangesAsync()
    {
        await _context.SaveChangesAsync();
        return true;
    }
}

