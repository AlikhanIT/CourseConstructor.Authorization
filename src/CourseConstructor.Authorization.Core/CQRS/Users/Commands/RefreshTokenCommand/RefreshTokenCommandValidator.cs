using CourseConstructor.Authorization.Core.CQRS.Users.Commands.RefreshTokenCommand;
using FluentValidation;

public class RefreshTokenCommandValidator : AbstractValidator<RefreshTokenCommand>
{
    public RefreshTokenCommandValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("Идентификатор пользователя не должен быть пустым.")
            .Must(id => id != Guid.Empty).WithMessage("Неверный формат идентификатора пользователя.");

        RuleFor(x => x.RefreshToken)
            .NotEmpty().WithMessage("Рефреш-токен не должен быть пустым.")
            .MinimumLength(10).WithMessage("Рефреш-токен должен содержать не менее 10 символов.");
    }
}