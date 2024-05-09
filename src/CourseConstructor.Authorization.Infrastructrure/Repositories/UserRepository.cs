using CourseConstructor.Authorization.Core.Entities.Models;
using CourseConstructor.Authorization.Core.Interfaces.Repositories;
using CourseConstructor.Authorization.Infrastructrure.Persistance;
using Microsoft.EntityFrameworkCore;

namespace CourseConstructor.Authorization.Infrastructrure.Repositories;

public class UserRepository : IUserRepository
{
    private readonly Context _context;

    public UserRepository(Context context)
    {
        _context = context;
    }

    public async Task<User?> GetByUsernameAsync(string username)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
    }

    public async Task<User?> GetByIdAsync(Guid userId)
    {
        return await _context.Users.FindAsync(userId);
    }

    public async Task AddUserAsync(User user)
    {
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateUserAsync(User user)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }
}