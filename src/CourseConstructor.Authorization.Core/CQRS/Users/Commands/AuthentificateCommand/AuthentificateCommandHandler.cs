using System.Security.Claims;
using Ardalis.Result;
using CourseConstructor.Authorization.Core.CQRS.Users.Commands.RegisterCommand;
using CourseConstructor.Authorization.Core.Entities.Models;
using CourseConstructor.Authorization.Core.Interfaces.Repositories;
using CourseConstructor.Authorization.Core.Interfaces.Services;
using MediatR;
using Microsoft.Extensions.Logging;

namespace CourseConstructor.Authorization.Core.CQRS.Users.Commands.AuthentificateCommand;

public class AuthentificateCommandHandler : IRequestHandler<AuthentificateCommand, Result<JwtToken>>
{
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IUserRepository _userRepository;
    private readonly ILogger<AuthentificateCommandHandler> _logger;
    public AuthentificateCommandHandler(
        IJwtTokenService jwtTokenService, 
        IUserRepository userRepository, 
        ILogger<AuthentificateCommandHandler> logger)
    {
        _jwtTokenService = jwtTokenService;
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<Result<JwtToken>> Handle(AuthentificateCommand request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Попытка аутентификации пользователя.");

        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            _logger.LogWarning("Неполные данные для аутентификации.");
            return Result<JwtToken>.Error("Пожалуйста, заполните все поля.");
        }

        var user = await _userRepository.GetByUsernameAsync(request.Username);
        if (user == null || !user.PasswordHash.Equals(PasswordHasher.HashPassword(request.Password)))
        {
            _logger.LogWarning("Неверная попытка входа для пользователя: {Username}", request.Username);
            return Result<JwtToken>.Error("Неверный логин или пароль.");
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Id.ToString())
        };
            
        var token = _jwtTokenService.GenerateTokens(user.Id.ToString(), claims);

        await _userRepository.UpdateUserAsync(user.SetRefreshToken(token.RefreshToken));

        _logger.LogInformation("Пользователь {Username} успешно вошел в систему.", user.Username);
        return Result<JwtToken>.Success(token);
    }
}