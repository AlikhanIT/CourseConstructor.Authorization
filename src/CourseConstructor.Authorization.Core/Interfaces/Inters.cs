using System.Security.Claims;

namespace CourseConstructor.Authorization.Core.Interfaces;

public interface IJwtTokenService
{
    JwtToken GenerateTokens(string userId, IEnumerable<Claim> claims);
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
}

public class JwtTokenSettings
{
    public string SecretKey { get; set; }
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public int AccessTokenExpirationMinutes { get; set; }
    public int RefreshTokenExpirationDays { get; set; }
}

public class JwtToken
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
}