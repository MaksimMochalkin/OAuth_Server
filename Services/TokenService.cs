namespace Services
{
    using Abstractions.Services;
    using Domain.Exceptions;
    using Microsoft.Extensions.Configuration;
    using Microsoft.IdentityModel.Tokens;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;

    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var tokenSettings = _configuration.GetSection("JwtTokenSettings");
            var secretKeyValue = tokenSettings["SecretKey"];

            if (string.IsNullOrWhiteSpace(secretKeyValue))
            {
                throw new ConfigurationParameterNotFound("Config param SecretKey not found");
            }

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKeyValue));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var isSuer = tokenSettings["Issuer"];
            if (string.IsNullOrWhiteSpace(isSuer))
            {
                throw new ConfigurationParameterNotFound("Config param Issuer not found");
            }

            var audience = tokenSettings["Audience"];
            if (string.IsNullOrWhiteSpace(audience))
            {
                throw new ConfigurationParameterNotFound("Config param Audience not found");
            }

            var validityHours = tokenSettings["AccessTokenValidityHours"];
            if (string.IsNullOrWhiteSpace(validityHours))
            {
                throw new ConfigurationParameterNotFound("Config param AccessTokenValidityHours not found");
            }

            var tokeOptions = new JwtSecurityToken(
                issuer: isSuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(Convert.ToInt32(validityHours)),
                signingCredentials: signinCredentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
            return tokenString;
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new ArgumentNullException("Token not transferred");
            }

            var secretKeyValue = _configuration.GetSection("JwtTokenSettings")?.GetSection("SecretKey")?.Value;

            if (string.IsNullOrWhiteSpace(secretKeyValue))
            {
                throw new ConfigurationParameterNotFound("Config param SecretKey not found");
            }

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKeyValue)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken is null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
    }
}
