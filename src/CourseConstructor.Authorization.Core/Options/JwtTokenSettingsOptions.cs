namespace CourseConstructor.Authorization.Core.Options;

public class JwtTokenSettingsOptions
{
    public static string SectionName { get; set; } = nameof(JwtTokenSettingsOptions);
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int AccessTokenExpirationMinutes { get; set; } = 60;
    public int RefreshTokenExpirationDays { get; set; } = 7;
}