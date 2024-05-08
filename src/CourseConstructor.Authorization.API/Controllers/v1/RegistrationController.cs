using System.Security.Claims;
using CourseConstructor.Authorization.API.Controllers.Base;
using CourseConstructor.Authorization.Core.Entities.Requests;
using CourseConstructor.Authorization.Core.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace CourseConstructor.Authorization.API.Controllers.v1;

/// <summary>
/// Контроллер для регистрации и авторизации пользователей.
/// </summary>
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/auth")]
[ApiController]
public class RegistrationController : BaseController
{
    private readonly IJwtTokenService _jwtTokenService;
    
    /// <summary>
    /// Конструктор инициализирует сервис генерации JWT токенов.
    /// </summary>
    /// <param name="jwtTokenService">Сервис, отвечающий за генерацию JWT токенов.</param>
    public RegistrationController(IJwtTokenService jwtTokenService) : base()
    {
        _jwtTokenService = jwtTokenService ?? throw new ArgumentNullException(nameof(jwtTokenService));
    }

    /// <summary>
    /// Простой тестовый эндпоинт для проверки работоспособности API.
    /// </summary>
    /// <returns>Ответ, показывающий, что тест завершен неудачно.</returns>
    [HttpGet("in")]
    public async Task<IActionResult> Test()
    {
        return Ok(new { IsSuccess = false });
    }

    /// <summary>
    /// Аутентифицирует пользователя на основе учетных данных.
    /// </summary>
    /// <param name="loginDto">Информация о входе пользователя.</param>
    /// <returns>Сгенерированный JWT токен, если аутентификация успешна.</returns>
    [HttpPost("authenticate")]
    [AllowAnonymous]
    public IActionResult Authenticate([FromBody] LoginDto loginDto)
    {
        if (loginDto == null || string.IsNullOrWhiteSpace(loginDto.Username) || string.IsNullOrWhiteSpace(loginDto.Password))
        {
            return BadRequest(new { Message = "Предоставлены некорректные учетные данные." });
        }

        var userId = "your_user_id";

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, userId)
        };

        var token = _jwtTokenService.GenerateTokens(userId, claims);

        if (token == null)
            return Unauthorized(new { Message = "Не удалось пройти аутентификацию." });

        return Ok(token);
    }

    /// <summary>
    /// Обновляет JWT токен на основе переданного рефреш-токена.
    /// </summary>
    /// <param name="refreshTokenDto">Содержит рефреш-токен для генерации новых токенов.</param>
    /// <returns>Новый JWT токен при корректном рефреш-токене.</returns>
    [HttpPost("refresh")]
    [AllowAnonymous]
    public IActionResult RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
    {
        if (refreshTokenDto == null || string.IsNullOrWhiteSpace(refreshTokenDto.RefreshToken))
        {
            return BadRequest(new { Message = "Некорректный рефреш-токен." });
        }

        var userId = "your_user_id"; 

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, userId)
        };

        var token = _jwtTokenService.GenerateTokens(userId, claims);

        if (token == null)
            return Unauthorized(new { Message = "Не удалось обновить токен." });

        return Ok(token);
    }
}
