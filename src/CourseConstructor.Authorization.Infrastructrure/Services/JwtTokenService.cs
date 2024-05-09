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
    
    public bool ValidateRefreshToken(string refreshToken)
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
        try
        {
            var claimsPrincipal = tokenHandler.ValidateToken(refreshToken, tokenValidationParameters, out var securityToken);
            var jwtToken = securityToken as JwtSecurityToken;

            if (jwtToken?.Payload.Exp != null)
            {
                var exp = DateTimeOffset.FromUnixTimeSeconds((long)jwtToken.Payload.Exp.Value).UtcDateTime;
                if (exp >= DateTime.UtcNow) return true;
                
                _logger.LogWarning("Рефреш-токен истек.");
                return false;

            }

            _logger.LogWarning("Поле exp отсутствует в рефреш-токене.");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Ошибка проверки рефреш-токена: {Message}", ex.Message);
            return false;
        }
    }
}