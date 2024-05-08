namespace CourseConstructor.Authorization.Core.Interfaces.Providers;

public interface IResourceRetriever
{
    public string GetResource(string key);
}