using System.Security.Claims;

namespace CourseConstructor.Authorization.Core.Interfaces;

public interface IJwtTokenService
{
    JwtToken GenerateTokens(string userId, IEnumerable<Claim> claims);
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
}

public class JwtToken
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
}