using CourseConstructor.Authorization.Core.CQRS.Users.Commands.RefreshTokenCommand;
using FluentValidation;

public class ValidateTokenCommandValidator : AbstractValidator<ValidateTokenCommand>
{
    public ValidateTokenCommandValidator()
    {
        RuleFor(x => x.AccessToken)
            .NotEmpty().WithMessage("Рефреш-токен не должен быть пустым.")
            .MinimumLength(10).WithMessage("Рефреш-токен должен содержать не менее 10 символов.");
    }
}