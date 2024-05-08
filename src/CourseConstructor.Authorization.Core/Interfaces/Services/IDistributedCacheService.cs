namespace CourseConstructor.Authorization.Core.Interfaces.Services;

public interface IDistributedCacheService
{
    Task<string?> GetString(string key) ;
    Task RemoveString(string key);
    Task SetString<T>(string key, T value, TimeSpan timeSpan);
}