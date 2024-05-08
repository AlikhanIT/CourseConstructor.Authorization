using CourseConstructor.Authorization.Core.Interfaces.Entities;
using CourseConstructor.Authorization.Core.Interfaces.Persistance;
using CourseConstructor.Authorization.Core.Interfaces.Providers;
using Microsoft.EntityFrameworkCore;

namespace CourseConstructor.Authorization.Infrastructrure.Persistance;

public class Context : DbContext, IContext
{
    private readonly IDateTimeProvider _dateTimeProvider;
    public Context(DbContextOptions<Context> options, IDateTimeProvider dateTimeProvider) 
        :base(options)
    {
    }
    
    public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    
    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        UpdateTimestamps();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    private void UpdateTimestamps()
    {
        var entries = ChangeTracker.Entries()
            .Where(e => e is { Entity: BaseEntity, State: EntityState.Added or EntityState.Modified });

        foreach (var entry in entries)
        {
            var entity = (BaseEntity)entry.Entity;
            if (entry.State == EntityState.Added)
                entity.CreatedDate = _dateTimeProvider.GetCurrentTime();

            entity.EditDate = _dateTimeProvider.GetCurrentTime();
        }
    }
}