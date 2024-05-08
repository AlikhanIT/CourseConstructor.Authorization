using System.Security.Claims;
using CourseConstructor.Authorization.API.Controllers.Base;
using CourseConstructor.Authorization.Core.Entities.Requests;
using CourseConstructor.Authorization.Core.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace CourseConstructor.Authorization.API.Controllers.v1;

[Route("register")]
[ApiController]
public class RegistrationController : BaseController
{
    private readonly IJwtTokenService _jwtTokenService;
    public RegistrationController(IJwtTokenService jwtTokenService) : base()
    {
        _jwtTokenService = jwtTokenService;
    }

    [HttpGet("in")]
    public async Task<IActionResult> Test()
    {
        return Ok(new {IsSuccess = false});
    }
    /// <summary>
    /// test
    /// </summary>
    /// <param name="loginDto"></param>
    /// <returns></returns>
    [HttpPost("authenticate")]
    public IActionResult Authenticate([FromBody] LoginDto loginDto)
    {
        var userId = "your_user_id";
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, userId) // Пример добавления идентификатора пользователя в токен как пример
        };

        var token = _jwtTokenService.GenerateTokens(userId, claims);
        return Ok(token);
    }

    [HttpPost("refresh")]
    public IActionResult RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
    {
        var userId = "your_user_id";
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, userId)
        };

        var token = _jwtTokenService.GenerateTokens(userId, claims);
        return Ok(token);
    }

}