using System;
using System.Threading.Tasks;
using Authenitcation.Infrastructure.Data;
using Authentication.Domain.Entities;
using Authentication.Domain.Enums;
using Authentication.Domain.Repositories;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Infrastructure.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly AutheDbContext _context;

        public UserRepository(AutheDbContext context)
        {
            _context = context;
        }
        public async Task<User?> GetByUsernameAsync(string username)
        {
            return await _context.Users
                .AsSplitQuery()
                .Include(u => u.UserProperty)  
                .Include(u => u.LoginPolicy)  
                .FirstOrDefaultAsync(u => u.UserName == username);        
        }

        public async Task<bool> ValidatePasswordAsync(string email, string password)
        {
            var user = await GetByUsernameAsync(email);
            if (user == null || user.UserProperty == null)
                return false;

            return user.UserProperty.Password == password;
        }
        public async Task<bool> CheckLoginPolicyAsync(string email)
        {
            var user = await GetUserByEmailAsync(email);
            if (user == null || user.LoginPolicy == null)
                return false;

            var policy = user.LoginPolicy;
            var now = DateTime.UtcNow;

            if (policy.LockTypes == LockTypes.TemporaryLock)
            {
                if (now >= policy.LockStartDateTime && now <= policy.LockEndDateTime)
                {
                    return false;
                }
            }
            else if (policy.LockTypes == LockTypes.PermanentLock)
            {
                return false; 
            }

            return true; 
        }

        public async Task<LoginPolicy> GetLoginPoliciesByUserID(string userId)
        {
                if (!long.TryParse(userId, out var userIdLong))
                    return null; // Invalid ID format

                return await _context.LoginPolicies
                    .FirstOrDefaultAsync(lp => lp.UserId == userIdLong);;        
        }





    public async Task<bool> SaveChangesAsync()
    {

        return await _context.SaveChangesAsync() > 0;

    }




        public async Task<User> GetUserByPhoneNumber(string phoneNumber)
        {
            User user = await _context.Users.FirstOrDefaultAsync(u=>u.Mobile == phoneNumber);
            return user;
        }

        public async Task<User?> GetUserByEmailAsync(string email)
        {
            return await _context.Users
                .AsSplitQuery()
                .Include(u => u.UserProperty)  
                .Include(u => u.LoginPolicy)  
                .FirstOrDefaultAsync(u => u.Email == email);           
        }

public async Task<(string Username, string Password)?> GetUserCredentialsAsync(string username)
{
    var user = await GetByUsernameAsync(username);

    if (user == null || user.UserProperty == null)
        return null;

    return (Username: user.Email, Password: user.UserProperty.Password);  
}




    }
}
