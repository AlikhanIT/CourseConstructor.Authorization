using CourseConstructor.Authorization.Core.Entities.Models;

namespace CourseConstructor.Authorization.Core.Interfaces.Repositories;

public interface IUserRepository
{
    Task<User?> GetByUsernameAsync(string username);
    Task<User?> GetByIdAsync(Guid userId);
    Task AddUserAsync(User user);
    Task UpdateUserAsync(User user);
}