using System.Security.Claims;
using CourseConstructor.Authorization.API.Controllers.Base;
using CourseConstructor.Authorization.Core.CQRS.Users.Commands.AuthentificateCommand;
using CourseConstructor.Authorization.Core.CQRS.Users.Commands.RefreshTokenCommand;
using CourseConstructor.Authorization.Core.CQRS.Users.Commands.RegisterCommand;
using CourseConstructor.Authorization.Core.Entities.Models;
using CourseConstructor.Authorization.Core.Entities.Requests;
using CourseConstructor.Authorization.Core.Interfaces.Providers;
using CourseConstructor.Authorization.Core.Interfaces.Repositories;
using CourseConstructor.Authorization.Core.Interfaces.Services;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace CourseConstructor.Authorization.API.Controllers.v1
{
    /// <summary>
    /// Контроллер для регистрации и авторизации пользователей.
    /// </summary>
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/auth")]
    [ApiController]
    public class RegistrationController : BaseController
    {
        private readonly IJwtTokenService _jwtTokenService;
        private readonly ISender _sender;
        private readonly IUserRepository _userRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<RegistrationController> _logger;
        /// <summary>
        /// Инъекция базовых зависимостей
        /// </summary>
        /// <param name="jwtTokenService"></param>
        /// <param name="userRepository"></param>
        /// <param name="logger"></param>
        /// <param name="sender"></param>
        /// <param name="dateTimeProvider"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public RegistrationController(
            IJwtTokenService jwtTokenService, 
            IUserRepository userRepository,
            ILogger<RegistrationController> logger, 
            ISender sender, 
            IDateTimeProvider dateTimeProvider) : base()
        {
            _jwtTokenService = jwtTokenService ?? throw new ArgumentNullException(nameof(jwtTokenService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _sender = sender;
            _dateTimeProvider = dateTimeProvider;
        }

        /// <summary>
        /// Регистрирует нового пользователя.
        /// </summary>
        /// <param name="registerDto">Данные для регистрации пользователя.</param>
        /// <returns>Результат регистрации.</returns>
        [HttpPost("register")]
        [ProducesResponseType(typeof(JwtToken), 200)]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            using (_logger.BeginScope("Registering user {Username}", registerDto?.Username))
            {
                _logger.LogInformation("Начало процесса регистрации.");
                var result = await _sender.Send(new RegisterCommand(registerDto!.Username, registerDto!.Password));

                if (result.IsSuccess)
                {
                    _logger.LogInformation("Регистрация пользователя {Username} завершена успешно.", registerDto.Username);
                    return Ok(result.Value);
                }
                
                _logger.LogError("Регистрация пользователя {Username} не завершена.", registerDto.Username);
                return BadRequest(result);
            }
        }

        /// <summary>
        /// Аутентифицирует пользователя на основе учетных данных.
        /// </summary>
        /// <param name="loginDto">Данные для входа пользователя.</param>
        /// <returns>Сгенерированный JWT токен, если аутентификация успешна.</returns>
        [HttpPost("authenticate")]
        [ProducesResponseType(typeof(JwtToken), 200)]
        [AllowAnonymous]
        public async Task<IActionResult> Authenticate([FromBody] LoginDto loginDto)
        {
            using (_logger.BeginScope("Registering user {Username}", loginDto?.Username))
            {
                _logger.LogInformation("Начало процесса аутентификации.");
                var result = await _sender.Send(new AuthentificateCommand(loginDto!.Username, loginDto!.Password));

                if (result.IsSuccess)
                {
                    _logger.LogInformation("Аутентификация пользователя {Username} завершена успешно.", loginDto.Username);
                    return Ok(result.Value);
                }
                
                _logger.LogError("Аутентификация пользователя {Username} не завершена.", loginDto.Username);
                return BadRequest(result);
            }
        }

        /// <summary>
        /// Обновляет JWT токен на основе переданного рефреш-токена.
        /// </summary>
        /// <param name="refreshTokenDto">Содержит рефреш-токен для генерации новых токенов.</param>
        /// <returns>Новый JWT токен при корректном рефреш-токене.</returns>
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(JwtToken), 200)]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
        {
            using (_logger.BeginScope("Registering user {Username}", refreshTokenDto?.UserId))
            {
                _logger.LogInformation("Начало процесса продления сеанса.");
                var result = await _sender.Send(new RefreshTokenCommand(refreshTokenDto!.UserId, refreshTokenDto!.RefreshToken));

                if (result.IsSuccess)
                {
                    _logger.LogInformation("Продление сеанса пользователя {Username} завершена успешно.", refreshTokenDto.UserId);
                    return Ok(result.Value);
                }
                
                _logger.LogError("Продление сеанса пользователя {Username} не завершена.", refreshTokenDto.UserId);
                return BadRequest(result);
            }
        }
    }
}
