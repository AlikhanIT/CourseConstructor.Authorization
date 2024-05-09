namespace CourseConstructor.Authorization.Core.Entities.Requests;

/// <summary>
/// DTO для авторизации пользователя.
/// </summary>
public class LoginDto
{
    /// <summary>
    /// Имя пользователя для регистрации.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Пароль для регистрации пользователя.
    /// </summary>
    public string Password { get; set; } = string.Empty;
}