namespace Services
{
    using Abstractions.Repositories;
    using Abstractions.Services;
    using Microsoft.Extensions.Configuration;

    public sealed class ServiceManager : IServiceManager
    {
        private readonly Lazy<ILoginService> _loginService;
        private readonly Lazy<IPasswordService> _passwordService;
        private readonly Lazy<ITokenService> _tokenService;
        private readonly IConfiguration _configuration;

        public ServiceManager(IRepositoryManager repositoryManager,
            IConfiguration configuration)
        {
            _configuration = configuration;
            _loginService = new Lazy<ILoginService>(() => new LoginService(repositoryManager, this));
            _passwordService = new Lazy<IPasswordService>(() => new PasswordService(_configuration));
            _tokenService = new Lazy<ITokenService>(() => new TokenService(_configuration));
        }

        public ILoginService LoginService => _loginService.Value;
        public IPasswordService PasswordService => _passwordService.Value;
        public ITokenService TokenService => _tokenService.Value;
        public IConfiguration Configuration => _configuration;
    }
}
