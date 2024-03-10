namespace Services
{
    using Abstractions.Services;
    using Domain.Exceptions;
    using Microsoft.Extensions.Configuration;
    using System.Security.Cryptography;
    using System.Text;

    public class PasswordService : IPasswordService
    {
        private int _iteration = 3;
        private readonly IConfiguration _configuration;

        public PasswordService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string ComputeHash(string password, string salt)
        {
            if (_iteration <= 0) return password;

            if (string.IsNullOrWhiteSpace(password)) 
            {
                throw new ArgumentNullException("Password did not transferred");
            }

            if (string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentNullException("Salt did not transferred");
            }

            var pepper = _configuration.GetSection("PasswordPaper").Value;

            if (string.IsNullOrWhiteSpace(pepper))
            {
                throw new ConfigurationParameterNotFound("Config param PasswordPaper not found");
            }

            using var sha256 = SHA256.Create();
            var passwordSaltPepper = $"{password}{salt}{pepper}";
            var byteValue = Encoding.UTF8.GetBytes(passwordSaltPepper);
            var byteHash = sha256.ComputeHash(byteValue);
            var hash = Convert.ToBase64String(byteHash);
            _iteration--;

            return ComputeHash(hash, salt);
        }

        public string GenerateSalt()
        {
            using var rng = RandomNumberGenerator.Create();
            var byteSalt = new byte[16];
            rng.GetBytes(byteSalt);
            var salt = Convert.ToBase64String(byteSalt);
            return salt;
        }
    }
}
