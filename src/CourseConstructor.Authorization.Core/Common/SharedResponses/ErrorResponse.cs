namespace CourseConstructor.Authorization.Core.Common.SharedResponses;

public class ErrorResponse
{
    public ErrorResponse() { }

    public ErrorResponse(
        int statusCode, 
        string message)
    {
        StatusCode = statusCode;
        Message = message;
    }

    public int StatusCode { get; set; }
    public string Message { get; set; } = string.Empty;
}