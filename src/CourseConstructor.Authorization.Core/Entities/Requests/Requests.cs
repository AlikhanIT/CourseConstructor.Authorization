namespace CourseConstructor.Authorization.Core.Entities.Requests;

public class LoginDto
{
    public string Username { get; set; }
    public string Password { get; set; }
}

/// <summary>
/// DTO для обновления токена с использованием рефреш-токена.
/// </summary>
public class RefreshTokenDto
{
    /// <summary>
    /// Идентификатор пользователя, для которого запрашивается обновление.
    /// </summary>
    public Guid UserId { get; set; } = Guid.Empty;

    /// <summary>
    /// Текущий рефреш-токен пользователя.
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;
}


/// <summary>
/// DTO для регистрации нового пользователя.
/// </summary>
public class RegisterDto
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