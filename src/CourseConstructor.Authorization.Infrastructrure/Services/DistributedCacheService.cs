using CourseConstructor.Authorization.Core.Interfaces.Services;
using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;

namespace CourseConstructor.Authorization.Infrastructrure.Services;

public class DistributedCacheService : IDistributedCacheService
{
    private readonly IDistributedCache _distributedCache;

    public DistributedCacheService(IDistributedCache distributedCache)
    {
        _distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
    }

    public async Task<string?> GetString(string key) =>
        await _distributedCache.GetStringAsync(key);
    public async Task RemoveString(string key) => await _distributedCache.RemoveAsync(key);
    
    public async Task SetString<T>(string key, T value, TimeSpan timeSpan)
    {
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = timeSpan
        };

        var serializedValue = JsonConvert.SerializeObject(value);
        await _distributedCache.SetStringAsync(key, serializedValue, options);
    }
}