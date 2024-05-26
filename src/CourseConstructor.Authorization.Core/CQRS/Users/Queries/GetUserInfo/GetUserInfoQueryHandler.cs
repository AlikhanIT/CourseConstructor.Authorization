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

public class GetUserInfoQueryHandler : IRequestHandler<GetUserInfoQuery, Result<User>>
{
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IUserRepository _userRepository;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly ILogger<ValidateTokenCommandHandler> _logger;
    public GetUserInfoQueryHandler(
        IJwtTokenService jwtTokenService, 
        IUserRepository userRepository, 
        ILogger<ValidateTokenCommandHandler> logger, IDateTimeProvider dateTimeProvider)
    {
        _jwtTokenService = jwtTokenService;
        _userRepository = userRepository;
        _logger = logger;
        _dateTimeProvider = dateTimeProvider;
    }

    public async Task<Result<User>> Handle(GetUserInfoQuery request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Попытка обновления токена.");

        if (string.IsNullOrWhiteSpace(request.AccessToken))
        {
            _logger.LogWarning("Пустой access-токен предоставлен для обновления.");
            return Result<User>.Error("Пожалуйста, предоставьте действительный access-токен." );
        }

        string userId = _jwtTokenService.GetUserIdFromToken(request.AccessToken);
        var userInfo = await _userRepository.GetByIdAsync(Guid.Parse(userId));

        return Result<User>.Success(userInfo);
    }
}