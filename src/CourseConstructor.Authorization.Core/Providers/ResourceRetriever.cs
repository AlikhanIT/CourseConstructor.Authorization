using CourseConstructor.Authorization.Core.Interfaces.Providers;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;

namespace CourseConstructors.CourseConstructors.Core.Providers;
public class ResourceRetriever : IResourceRetriever
{
    private readonly IStringLocalizer<ResourceRetriever> _localizer;
    private readonly ILogger<ResourceRetriever> _logger;

    public ResourceRetriever(IStringLocalizer<ResourceRetriever> localizer,
        ILogger<ResourceRetriever> logger)
    {
        _localizer = localizer;
        _logger = logger;
    }

    public string GetResource(string key)
    {
        _logger.LogInformation("Достаем из ресурса локализованную строку по ключу {key}", key);
        return _localizer[key];
    }
}