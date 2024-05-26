using System.Security.Claims;
using System.Security.Cryptography;
using CourseConstructor.Authorization.Core.Interfaces.Providers;
using CourseConstructor.Authorization.Core.Options;
using CourseConstructor.Authorization.Infrastructrure.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace CourseConstructor.Authorization.Test;

public class UnitTest1
{
    private readonly JwtTokenService _jwtTokenService;
    private readonly Mock<IDateTimeProvider> _mockDateTimeProvider = new Mock<IDateTimeProvider>();
    private readonly Mock<ILogger<JwtTokenService>> _mockLogger = new Mock<ILogger<JwtTokenService>>();

    private readonly JwtTokenSettingsOptions _jwtTokenSettingsOptions = new JwtTokenSettingsOptions
    {
        SecretKey = "verysecretkey12345",
        AccessTokenExpirationMinutes = 15,
        RefreshTokenExpirationDays = 7,
        Issuer = "TestIssuer",
        Audience = "TestAudience"
    };

    public UnitTest1()
    {
        _mockDateTimeProvider.Setup(p => p.GetCurrentTime()).Returns(DateTime.UtcNow);
        var mockOptions = new Mock<IOptions<JwtTokenSettingsOptions>>();
        mockOptions.Setup(m => m.Value).Returns(_jwtTokenSettingsOptions);
        _jwtTokenService = new JwtTokenService(mockOptions.Object, _mockDateTimeProvider.Object, _mockLogger.Object);
    }

    [Fact]
    public void GenerateTokens_ShouldReturnValidTokens()
    {
        // Arrange
        var userId = "user1";
        var claims = new List<Claim> { new Claim(ClaimTypes.Name, userId) };

        // Act
        var jwtToken = _jwtTokenService.GenerateTokens(userId, claims);

        // Assert
        Assert.NotNull(jwtToken.AccessToken);
        Assert.NotNull(jwtToken.RefreshToken);
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_ShouldReturnPrincipal()
    {
        // Arrange
        var token = _jwtTokenService.GenerateTokens("user1", new List<Claim>()).AccessToken;
        _mockDateTimeProvider.Setup(p => p.GetCurrentTime())
            .Returns(DateTime.UtcNow.AddDays(-1));

        // Act
        var principal = _jwtTokenService.GetPrincipalFromExpiredToken(token);

        // Assert
        Assert.NotNull(principal);
        Assert.Equal("user1", principal.Identity.Name);
    }

    [Fact]
    public void ValidateToken_ShouldReturnTrueForValidToken()
    {
        // Arrange
        var token = _jwtTokenService.GenerateTokens("user1", new List<Claim>()).AccessToken;

        // Act
        var isValid = _jwtTokenService.ValidateToken(token);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void GetUserIdFromToken_ShouldExtractUserId()
    {
        // Arrange
        var claims = new List<Claim> { new Claim("uid", "12345") };
        var token = _jwtTokenService.GenerateTokens("user1", claims).AccessToken;

        // Act
        var userId = _jwtTokenService.GetUserIdFromToken(token);

        // Assert
        Assert.Equal("12345", userId);
    }

}