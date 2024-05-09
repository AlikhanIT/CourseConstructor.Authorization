namespace CourseConstructor.Authorization.Core.Entities.Requests;

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
