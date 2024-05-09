using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CourseConstructor.Authorization.Core.Interfaces;
using CourseConstructor.Authorization.Core.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CourseConstructor.Authorization.Infrastructrure.Services;

public class JwtTokenService : IJwtTokenService
{
    private readonly JwtTokenSettingsOptions _jwtTokenSettingsOptions;

    public JwtTokenService(IOptions<JwtTokenSettingsOptions> jwtTokenSettingsOptions)
    {
        _jwtTokenSettingsOptions = jwtTokenSettingsOptions.Value;
    }

    public JwtToken GenerateTokens(string userId, IEnumerable<Claim> claims)
    {
        try
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettingsOptions.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var accessTokenExpiration = DateTime.UtcNow.AddMinutes(_jwtTokenSettingsOptions.AccessTokenExpirationMinutes);
            var refreshTokenExpiration = DateTime.UtcNow.AddDays(_jwtTokenSettingsOptions.RefreshTokenExpirationDays);

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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtTokenSettingsOptions.SecretKey)),
            ValidateIssuer = true,
            ValidIssuer = _jwtTokenSettingsOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtTokenSettingsOptions.Audience,
            ValidateLifetime = false
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