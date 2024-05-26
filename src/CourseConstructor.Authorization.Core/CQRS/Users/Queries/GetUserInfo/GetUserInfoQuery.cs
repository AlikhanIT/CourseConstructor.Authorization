using Ardalis.Result;
using CourseConstructor.Authorization.Core.Entities.Models;
using MediatR;

namespace CourseConstructor.Authorization.Core.CQRS.Users.Commands.RefreshTokenCommand;

public record GetUserInfoQuery(string AccessToken) : IRequest<Result<User>>;
