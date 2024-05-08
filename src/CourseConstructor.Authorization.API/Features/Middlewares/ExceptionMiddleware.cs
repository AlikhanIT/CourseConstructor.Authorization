using CourseConstructor.Authorization.Core.Common.SharedResponses;
using Newtonsoft.Json;

namespace CourseConstructor.Authorization.API.Features.Middlewares;

/// <summary>
/// Миддлвэйр для обработки ошибок
/// </summary>
public class ExceptionMiddleware
{
    private readonly RequestDelegate _next;  
    
    /// <summary>
    /// Конструктор с регистрацией миддлвэйра для вызова следующей функции
    /// </summary>
    /// <param name="next"></param>
    /// <exception cref="ArgumentNullException"></exception>
    public ExceptionMiddleware(RequestDelegate next)  
    {  
        _next = next ?? throw new ArgumentNullException(nameof(next));  
    }  
    /// <summary>
    /// Обработчик миддлвэйра ошибок
    /// </summary>
    /// <param name="context"></param>
    public async Task InvokeAsync(HttpContext context)  
    {
        try
        {
            await _next(context);  
        }
        catch (Exception e)
        {
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;

            var errorModel = new ErrorResponse(context.Response.StatusCode, e.Message);
            var jsonResponse = JsonConvert.SerializeObject(errorModel);

            await context.Response.WriteAsync(jsonResponse);
        }
    }
}