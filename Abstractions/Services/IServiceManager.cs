namespace Abstractions.Services
{
    using Microsoft.Extensions.Configuration;

    public interface IServiceManager
    {
        public ITokenService TokenService { get; }
        public ILoginService LoginService { get; }
        public IPasswordService PasswordService { get; }
        public IConfiguration Configuration { get; }
    }
}
