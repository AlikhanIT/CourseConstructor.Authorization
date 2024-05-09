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

public class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, Result<JwtToken>>
{
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IUserRepository _userRepository;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly ILogger<RefreshTokenCommandHandler> _logger;
    public RefreshTokenCommandHandler(
        IJwtTokenService jwtTokenService, 
        IUserRepository userRepository, 
        ILogger<RefreshTokenCommandHandler> logger, IDateTimeProvider dateTimeProvider)
    {
        _jwtTokenService = jwtTokenService;
        _userRepository = userRepository;
        _logger = logger;
        _dateTimeProvider = dateTimeProvider;
    }

    public async Task<Result<JwtToken>> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Попытка обновления токена.");

        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            _logger.LogWarning("Пустой рефреш-токен предоставлен для обновления.");
            return Result<JwtToken>.Error("Пожалуйста, предоставьте действительный рефреш-токен." );
        }

        var user = await _userRepository.GetByIdAsync(request.UserId);
        bool isValid = _jwtTokenService.ValidateRefreshToken(request.RefreshToken);

        if (user == null || user.RefreshToken != request.RefreshToken || !isValid)
        {
            _logger.LogWarning("Недействительный рефреш-токен или пользователь не найден: {UserId}", request.UserId);
            return Result<JwtToken>.Error("Недействительный или истекший рефреш-токен.");
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Id.ToString())
        };

        var token = _jwtTokenService.GenerateTokens(user.Id.ToString(), claims);
        if (token == null)
        {
            _logger.LogError("Ошибка генерации новых токенов для пользователя: {UserId}", user.Id);
            return Result<JwtToken>.Error("Ошибка генерации токенов." );
        }

        user.RefreshToken = token.RefreshToken;
        user.RefreshTokenExpiry = _dateTimeProvider.GetCurrentTime().AddDays(7);

        await _userRepository.UpdateUserAsync(user);

        _logger.LogInformation("Успешное обновление токена для пользователя: {UserId}", user.Id);
        return Result<JwtToken>.Success(token);
    }
}