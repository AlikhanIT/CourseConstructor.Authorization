using System.Security.Claims;
using Ardalis.Result;
using CourseConstructor.Authorization.Core.Entities.Models;
using CourseConstructor.Authorization.Core.Interfaces.Repositories;
using CourseConstructor.Authorization.Core.Interfaces.Services;
using MediatR;
using Microsoft.Extensions.Logging;

namespace CourseConstructor.Authorization.Core.CQRS.Users.Commands.RegisterCommand;

public class RegisterCommandHandler : IRequestHandler<RegisterCommand, Result<JwtToken>>
{
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IUserRepository _userRepository;
    private readonly ILogger<RegisterCommandHandler> _logger;
    public RegisterCommandHandler(
        IJwtTokenService jwtTokenService, 
        IUserRepository userRepository, 
        ILogger<RegisterCommandHandler> logger)
    {
        _jwtTokenService = jwtTokenService;
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<Result<JwtToken>> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Начало регистрации пользователя.");
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            _logger.LogWarning("Неполные данные регистрации предоставлены.");
            return Result<JwtToken>.Error("Пожалуйста, заполните все поля.");
        }

        var existingUser = await _userRepository.GetByUsernameAsync(request.Username);
        if (existingUser != null)
        {
            _logger.LogWarning("Попытка регистрации с уже занятым логином: {Username}", request.Username);
            return Result<JwtToken>.Error("Этот логин уже используется.");
        }

        var passwordHash = PasswordHasher.HashPassword(request.Password);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = request.Username,
            PasswordHash = passwordHash
        };
            
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Id.ToString())
        };
        var token = _jwtTokenService.GenerateTokens(user.Id.ToString(), claims);

        await _userRepository.AddUserAsync(user.SetRefreshToken(token.RefreshToken));

        _logger.LogInformation("Пользователь {Username} успешно зарегистрирован.", user.Username);
        return Result<JwtToken>.Success(token);
    }
}