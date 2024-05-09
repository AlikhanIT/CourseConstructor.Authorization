using CourseConstructor.Authorization.Core.Entities.Models;
using Microsoft.EntityFrameworkCore;

namespace CourseConstructor.Authorization.Core.Interfaces.Persistance;

public interface IContext
{ 
    public DbSet<User> Users { get; set; }
}