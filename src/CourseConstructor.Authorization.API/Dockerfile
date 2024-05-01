FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["CourseConstructor.Authorization.API/CourseConstructor.Authorization.API.csproj", "CourseConstructor.Authorization.API/"]
RUN dotnet restore "CourseConstructor.Authorization.API/CourseConstructor.Authorization.API.csproj"
COPY . .
WORKDIR "/src/CourseConstructor.Authorization.API"
RUN dotnet build "CourseConstructor.Authorization.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "CourseConstructor.Authorization.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "CourseConstructor.Authorization.API.dll"]
