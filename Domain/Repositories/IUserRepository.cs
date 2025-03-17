using System.Threading.Tasks;
using Authentication.Domain.Entities;

namespace Authentication.Domain.Repositories
{
    public interface IUserRepository
    {
        Task<User?> GetUserByEmailAsync(string email);
        Task<bool> ValidatePasswordAsync(string email, string password);
        Task<bool> CheckLoginPolicyAsync(string email);
        Task<LoginPolicy?> GetLoginPoliciesByUserID(string userId);
        Task<(string Username, string Password)?> GetUserCredentialsAsync(string username);
        Task<bool> SaveChangesAsync();

        Task<User> GetUserByPhoneNumber(string phoneNumber);
    }
}
