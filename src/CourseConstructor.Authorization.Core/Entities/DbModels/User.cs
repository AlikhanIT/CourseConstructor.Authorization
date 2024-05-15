using System.ComponentModel.DataAnnotations;

namespace CourseConstructor.Authorization.Core.Entities.Models;

public class User
{
    [Key]
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    [EmailAddress(ErrorMessage = "Invalid Email Address")]
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime RefreshTokenExpiry { get; set; }

    public User SetRefreshToken(string refreshToken)
    {
        RefreshToken = refreshToken;

        return this;
    }
}