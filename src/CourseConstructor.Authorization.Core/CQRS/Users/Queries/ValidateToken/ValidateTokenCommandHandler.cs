using System.Security.Claims;
using Ardalis.Result;
using CourseConstructor.Authorization.Core.CQRS.Users.Commands.RegisterCommand;
using CourseConstructor.Authorization.Core.Entities.Models;
using CourseConstructor.Authorization.Core.Interfaces.Providers;
using CourseConstructor.Authorization.Core.Interfaces.Repositories;
using CourseConstructor.Authorization.Core.Interfaces.Services;
using MediatR;
using Microsoft.Extensions.Logging;

namespace CourseConstructor.Authorization.Core.CQRS.Users.Commands.RefreshTokenCommand;

public class ValidateTokenCommandHandler : IRequestHandler<ValidateTokenCommand, Result<bool>>
{
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IUserRepository _userRepository;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly ILogger<ValidateTokenCommandHandler> _logger;
    public ValidateTokenCommandHandler(
        IJwtTokenService jwtTokenService, 
        IUserRepository userRepository, 
        ILogger<ValidateTokenCommandHandler> logger, IDateTimeProvider dateTimeProvider)
    {
        _jwtTokenService = jwtTokenService;
        _userRepository = userRepository;
        _logger = logger;
        _dateTimeProvider = dateTimeProvider;
    }

    public async Task<Result<bool>> Handle(ValidateTokenCommand request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Попытка обновления токена.");

        if (string.IsNullOrWhiteSpace(request.AccessToken))
        {
            _logger.LogWarning("Пустой access-токен предоставлен для обновления.");
            return Result<bool>.Error("Пожалуйста, предоставьте действительный access-токен." );
        }

        bool isValid = _jwtTokenService.ValidateToken(request.AccessToken);

        return Result<bool>.Success(isValid);
    }
}