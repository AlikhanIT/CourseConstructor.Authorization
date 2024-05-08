namespace CourseConstructor.Authorization.Core.Common.VersionMode;

public static class VersionMode
{
    public static string Production { get; set; } = nameof(Production);
    public static string Test { get; set; } = nameof(Test);
    public static string Development { get; set; } = nameof(Development);
}