﻿using Ardalis.Result;
using CourseConstructor.Authorization.Core.Entities.Models;
using MediatR;

namespace CourseConstructor.Authorization.Core.CQRS.Users.Commands.RegisterCommand;

public record RegisterCommand(string Username,  string Password) : IRequest<Result<JwtToken>>;
