using MediatR;
using Microsoft.Extensions.Logging;

namespace CourseConstructor.Authorization.Core.Common.Behaivors;

public class LoggingBehaivor<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse> where TRequest : IRequest<TResponse>
{
    private readonly ILogger<LoggingBehaivor<TRequest, TResponse>> _logger;

    public LoggingBehaivor(ILogger<LoggingBehaivor<TRequest, TResponse>> logger)
    {
        _logger = logger;
    }

    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation($"Before execution for {typeof(TRequest).Name}");

            return await next();
        }
        finally
        {
            _logger.LogError($"After execution for {typeof(TRequest).Name}");
        }
    }
}