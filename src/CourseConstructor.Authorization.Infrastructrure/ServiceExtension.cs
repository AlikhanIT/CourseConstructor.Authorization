using CourseConstructor.Authorization.Core.Interfaces.Persistance;
using CourseConstructor.Authorization.Core.Interfaces.Services;
using CourseConstructor.Authorization.Infrastructrure.Persistance;
using CourseConstructor.Authorization.Infrastructrure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CourseConstructors.CourseConstructors.Infrastructure;

public static class ServiceExtension
{
    public static IServiceCollection ConfigurePersistance(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<Context>(options =>
            options.UseNpgsql(
                configuration.GetConnectionString("DefaultConnection")));
        services.AddScoped<IContext, Context>();
        
        return services;
    }
    
    public static IServiceCollection ConfigureCaching(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddStackExchangeRedisCache(action=>{
            var connection = configuration.GetConnectionString("Redis");
            action.Configuration = connection;
        });

        return services;
    }
    
    public static IServiceCollection ConfigureServices(this IServiceCollection services)
    {
        services.AddScoped<IDistributedCacheService, DistributedCacheService>();

        return services;
    }
}