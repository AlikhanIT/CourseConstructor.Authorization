using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CourseConstructor.Authorization.Core.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CourseConstructor.Authorization.Infrastructrure.Services;

public class JwtTokenService : IJwtTokenService
{
    private readonly JwtTokenSettings _jwtTokenSettings;

    public JwtTokenService(IOptions<JwtTokenSettings> jwtTokenSettings)
    {
        _jwtTokenSettings = jwtTokenSettings.Value;
    }

    public JwtToken GenerateTokens(string userId, IEnumerable<Claim> claims)
    {
        try
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var accessTokenExpiration = DateTime.UtcNow.AddMinutes(_jwtTokenSettings.AccessTokenExpirationMinutes);
            var refreshTokenExpiration = DateTime.UtcNow.AddDays(_jwtTokenSettings.RefreshTokenExpirationDays);

            var accessToken = new JwtSecurityToken(
                _jwtTokenSettings.Issuer,
                _jwtTokenSettings.Audience,
                claims,
                expires: accessTokenExpiration,
                signingCredentials: creds
            );

            var refreshToken = new JwtSecurityToken(
                _jwtTokenSettings.Issuer,
                _jwtTokenSettings.Audience,
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
        catch (Exception ex)
        {
            return new JwtToken();
        }

    }

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettings.SecretKey)),
            ValidateIssuer = true,
            ValidIssuer = _jwtTokenSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtTokenSettings.Audience,
            ValidateLifetime = false // because tokens have expiration time
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken securityToken;
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
        var jwtSecurityToken = securityToken as JwtSecurityToken;
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");

        return principal;
    }
}