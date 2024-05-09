using System.Reflection;
using CourseConstructor.Authorization.API.Features.Middlewares;
using CourseConstructor.Authorization.Core.Common.Behaivors;
using FluentValidation;
using FluentValidation.AspNetCore;
using MediatR;
using Microsoft.OpenApi.Models;
using Serilog;

namespace CourseConstructor.Authorization.API;

internal static class ServiceExtension
{
    internal static IServiceCollection ConfigureVersioning(this IServiceCollection services)
    {
        return services
            .AddApiVersioning();
    }
    internal static IServiceCollection ConfigureMediatR(this IServiceCollection services)
    {
        return services.AddMediatR(typeof(Program))
            .AddScoped(typeof(IPipelineBehavior<,>), typeof(LoggingBehaivor<,>))
            .AddFluentValidationAutoValidation()
            .AddValidatorsFromAssembly(Assembly.GetExecutingAssembly());
    }
    
    internal static void ConfigureSerilog(this WebApplicationBuilder host, IConfiguration configuration)
    {
        Log.Logger = new LoggerConfiguration()
            .ReadFrom.Configuration(configuration)
            .CreateLogger();

        host.Logging.ClearProviders();
        host.Logging.AddSerilog();
    }
    
    internal static IServiceCollection ConfigureSwaggerGen(this IServiceCollection services)
    {
        services.AddSwaggerGen(c => {
            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            c.IncludeXmlComments(xmlPath);
            c.SwaggerDoc( "v1", new OpenApiInfo()
            {
                Version = "v1",
                Title = "Shop API",
                Description = "Пример ASP .NET Core Web API",
                Contact = new OpenApiContact
                {
                    Name = "Пример контакта",
                    Url = new Uri("https://example.com/contact")
                },
                License = new OpenApiLicense
                {
                    Name = "Пример лицензии",
                    Url = new Uri("https://example.com/license")
                }
            });
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = @"Введите JWT токен авторизации.",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey,
                BearerFormat = "JWT",
                Scheme = "Bearer"
            });
        });
        
        return services;
    }
    
    internal static WebApplication ApplyMiddlewares(this WebApplication app)
    {
        app.UseMiddleware<ExceptionMiddleware>();

        return app;
    }
}