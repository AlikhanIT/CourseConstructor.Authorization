using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using CourseConstructor.Authorization.API.Controllers.Base;
using CourseConstructor.Authorization.Core.Entities;
using CourseConstructor.Authorization.Core.Entities.Models;
using CourseConstructor.Authorization.Core.Entities.Requests;
using CourseConstructor.Authorization.Core.Interfaces;
using CourseConstructor.Authorization.Core.Interfaces.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

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
        private readonly IUserRepository _userRepository;

        public RegistrationController(
            IJwtTokenService jwtTokenService, 
            IUserRepository userRepository) : base()
        {
            _jwtTokenService = jwtTokenService ?? throw new ArgumentNullException(nameof(jwtTokenService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        }

        /// <summary>
        /// Регистрирует нового пользователя.
        /// </summary>
        /// <param name="registerDto">Данные для регистрации пользователя.</param>
        /// <returns>Результат регистрации.</returns>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            if (registerDto == null || string.IsNullOrWhiteSpace(registerDto.Username) || string.IsNullOrWhiteSpace(registerDto.Password))
                return BadRequest(new { Message = "Пожалуйста, заполните все поля." });

            // Проверяем, не занят ли уже логин.
            var existingUser = await _userRepository.GetByUsernameAsync(registerDto.Username);
            if (existingUser != null)
                return Conflict(new { Message = "Этот логин уже используется." });

            // Создаем хэш пароля.
            var passwordHash = HashPassword(registerDto.Password);

            // Создаем и сохраняем нового пользователя.
            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = registerDto.Username,
                PasswordHash = passwordHash
            };
            
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Id.ToString())
            };
            var token = _jwtTokenService.GenerateTokens(user.Id.ToString(), claims);

            await _userRepository.AddUserAsync(user.SetRefreshToken(token.RefreshToken));

            return Ok(token);
        }

        /// <summary>
        /// Аутентифицирует пользователя на основе учетных данных.
        /// </summary>
        /// <param name="loginDto">Данные для входа пользователя.</param>
        /// <returns>Сгенерированный JWT токен, если аутентификация успешна.</returns>
        [HttpPost("authenticate")]
        [AllowAnonymous]
        public async Task<IActionResult> Authenticate([FromBody] LoginDto loginDto)
        {
            if (loginDto == null || string.IsNullOrWhiteSpace(loginDto.Username) || string.IsNullOrWhiteSpace(loginDto.Password))
                return BadRequest(new { Message = "Пожалуйста, заполните все поля." });

            // Поиск пользователя по логину.
            var user = await _userRepository.GetByUsernameAsync(loginDto.Username);
            if (user == null || !VerifyPassword(loginDto.Password, user.PasswordHash))
                return Unauthorized(new { Message = "Неверный логин или пароль." });

            // Генерация JWT токенов.
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Id.ToString())
            };
            
            var token = _jwtTokenService.GenerateTokens(user.Id.ToString(), claims);

            _userRepository.UpdateUserAsync(user.SetRefreshToken(token.RefreshToken));

            return Ok(token);
        }

        /// <summary>
        /// Обновляет JWT токен на основе переданного рефреш-токена.
        /// </summary>
        /// <param name="refreshTokenDto">Содержит рефреш-токен для генерации новых токенов.</param>
        /// <returns>Новый JWT токен при корректном рефреш-токене.</returns>
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
        {
            if (refreshTokenDto == null || string.IsNullOrWhiteSpace(refreshTokenDto.RefreshToken))
                return BadRequest(new { Message = "Пожалуйста, предоставьте действительный рефреш-токен." });

            // Найдите пользователя по его рефреш-токену.
            var user = await _userRepository.GetByIdAsync(refreshTokenDto.UserId);
            if (user == null || user.RefreshToken != refreshTokenDto.RefreshToken)
            {
                return Unauthorized(new { Message = "Недействительный или истекший рефреш-токен." });
            }

            // Генерируем новые токены и обновляем рефреш-токен.
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Id.ToString())
            };

            var token = _jwtTokenService.GenerateTokens(user.Id.ToString(), claims);
            if (token == null)
                return Unauthorized(new { Message = "Ошибка генерации токенов." });

            // Обновляем рефреш-токен пользователя.
            user.RefreshToken = token.RefreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7); // Пример: 7 дней для рефреш-токена.

            await _userRepository.UpdateUserAsync(user);

            return Ok(token);
        }

        /// <summary>
        /// Хэширует пароль с использованием случайной соли.
        /// </summary>
        /// <param name="password">Пароль, который нужно захэшировать.</param>
        /// <returns>Хэшированный пароль.</returns>
        private string HashPassword(string password)
        {
            // Используем криптографическое хэширование пароля с солью.
            byte[] salt = new byte[16];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                rng.GetBytes(salt);

            var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32));

            return $"{Convert.ToBase64String(salt)}:{hashed}";
        }

        /// <summary>
        /// Проверяет пароль на соответствие хэшированному значению.
        /// </summary>
        /// <param name="password">Оригинальный пароль.</param>
        /// <param name="storedHash">Хэшированное значение пароля, сохраненное в базе данных.</param>
        /// <returns>True, если пароль совпадает с хэшированным значением, иначе False.</returns>
        private bool VerifyPassword(string password, string storedHash)
        {
            var parts = storedHash.Split(':');
            if (parts.Length != 2)
                return false;

            var salt = Convert.FromBase64String(parts[0]);
            var storedPasswordHash = parts[1];

            var computedHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32));

            return storedPasswordHash == computedHash;
        }
    }
}
