using System.Security.Claims;
using CourseConstructor.Authorization.Core.Entities.Models;

namespace CourseConstructor.Authorization.Core.Interfaces.Services;

public interface IJwtTokenService
{
    JwtToken GenerateTokens(string userId, IEnumerable<Claim> claims);
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    bool ValidateRefreshToken(string refreshToken);
}