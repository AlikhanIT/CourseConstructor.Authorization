using Ardalis.Result;
using MediatR;

namespace CourseConstructor.Authorization.Core.CQRS.Users.Commands.RefreshTokenCommand;

public record ValidateTokenCommand(string AccessToken) : IRequest<Result<bool>>;
