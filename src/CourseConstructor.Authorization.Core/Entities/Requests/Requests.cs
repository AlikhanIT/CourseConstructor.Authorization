namespace CourseConstructor.Authorization.Core.Entities.Requests;

public class LoginDto
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class RefreshTokenDto
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
}
