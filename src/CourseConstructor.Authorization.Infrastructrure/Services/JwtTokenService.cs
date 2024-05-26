using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CourseConstructor.Authorization.Core.Entities.Models;
using CourseConstructor.Authorization.Core.Interfaces.Providers;
using CourseConstructor.Authorization.Core.Interfaces.Services;
using CourseConstructor.Authorization.Core.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CourseConstructor.Authorization.Infrastructrure.Services;

public class JwtTokenService : IJwtTokenService
{
    private readonly JwtTokenSettingsOptions _jwtTokenSettingsOptions;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly ILogger<JwtTokenService> _logger;

    public JwtTokenService(
        IOptions<JwtTokenSettingsOptions> jwtTokenSettingsOptions, 
        IDateTimeProvider dateTimeProvider,
        ILogger<JwtTokenService> logger)
    {
        _dateTimeProvider = dateTimeProvider;
        _logger = logger;
        _jwtTokenSettingsOptions = jwtTokenSettingsOptions.Value;
    }

    public JwtToken GenerateTokens(string userId, IEnumerable<Claim> claims)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettingsOptions.SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var accessTokenExpiration = _dateTimeProvider.GetCurrentTime().AddMinutes(_jwtTokenSettingsOptions.AccessTokenExpirationMinutes);
        var refreshTokenExpiration = _dateTimeProvider.GetCurrentTime().AddDays(_jwtTokenSettingsOptions.RefreshTokenExpirationDays);

        var accessToken = new JwtSecurityToken(
            _jwtTokenSettingsOptions.Issuer,
            _jwtTokenSettingsOptions.Audience,
            claims,
            expires: accessTokenExpiration,
            signingCredentials: creds
        );

        var refreshToken = new JwtSecurityToken(
            _jwtTokenSettingsOptions.Issuer,
            _jwtTokenSettingsOptions.Audience,
            claims,
            expires: refreshTokenExpiration,
            signingCredentials: creds
        );

        return new JwtToken
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
            RefreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken)
        };
    }

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettingsOptions.SecretKey)),
            ValidateIssuer = true,
            ValidIssuer = _jwtTokenSettingsOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtTokenSettingsOptions.Audience,
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");

        return principal;
    }
    public bool ValidateToken(string accessToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettingsOptions.SecretKey)),
            ValidateIssuer = true,
            ValidIssuer = _jwtTokenSettingsOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtTokenSettingsOptions.Audience,
            ValidateLifetime = true, 
            ClockSkew = TimeSpan.Zero 
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out var securityToken);
            return securityToken is JwtSecurityToken jwtSecurityToken && jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
        }
        catch (SecurityTokenExpiredException)
        {
            _logger.LogWarning("Токен доступа истек.");
            return false;
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogWarning("Ошибка валидации токена доступа: {Message}", ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError("Ошибка при валидации токена: {Message}", ex.Message);
            return false;
        }
    }
/// <summary>
    /// Извлекает идентификатор пользователя из предоставленного JWT токена.
    /// </summary>
    /// <param name="token">JWT токен, из которого необходимо извлечь идентификатор пользователя.</param>
    /// <returns>Идентификатор пользователя, если токен действителен; в противном случае, null.</returns>
    public string? GetUserIdFromToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetTokenValidationParameters();

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                _logger.LogWarning("Недействительный JWT токен.");
                return null;
            }

            var userIdClaim = principal.FindFirst("uid") ?? principal.FindFirst(ClaimTypes.Name);

            if (userIdClaim != null)
            {
                return userIdClaim.Value;
            }
            _logger.LogWarning("Утверждение с идентификатором пользователя не найдено в токене.");
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError("Произошло исключение при извлечении идентификатора пользователя из токена: {Message}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Возвращает параметры валидации токена.
    /// </summary>
    /// <returns>Параметры валидации TokenValidationParameters, используемые для проверки JWT токенов.</returns>
    private TokenValidationParameters GetTokenValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettingsOptions.SecretKey)),
            ValidateIssuer = true,
            ValidIssuer = _jwtTokenSettingsOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtTokenSettingsOptions.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    }
}