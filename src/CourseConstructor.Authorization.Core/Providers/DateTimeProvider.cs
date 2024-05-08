using CourseConstructor.Authorization.Core.Interfaces.Providers;

namespace CourseConstructor.Authorization.Core.Providers;

public class DateTimeProvider : IDateTimeProvider
{
    public DateTime GetCurrentTime() => DateTime.UtcNow.AddHours(5);
}