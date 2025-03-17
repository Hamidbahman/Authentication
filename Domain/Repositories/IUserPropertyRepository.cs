using System;
using System.Threading.Tasks;
using Authentication.Domain.Entities;

namespace Domain.Repositories;

public interface IUserPropertyRepository
{
    Task<ConfigurationPassword?> GetConfigurationPasswordByUserIdAsync(long configurationPasswordId);

    Task<bool> SaveChangesAsync();
}

