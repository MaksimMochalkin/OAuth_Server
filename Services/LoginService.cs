namespace Services
{
    using Abstractions.Repositories;
    using Abstractions.Services;
    using Contracts.RequestResponses;
    using Contracts.Requests;
    using Domain.Entities;
    using Domain.Exceptions;
    using System.Security.Claims;

    public class LoginService : ILoginService
    {
        private readonly IRepositoryManager _repositoryManager;
        private readonly IServiceManager _serviceManager;

        public LoginService(IRepositoryManager repositoryManager,
            IServiceManager serviceManager)
        {
            _repositoryManager = repositoryManager;
            _serviceManager = serviceManager;
        }

        public async Task<AuthenticatedResponse> LogIn(LoginRequest request)
        {
            ValidateLoginRequest(request);
            var loginInfo = await _repositoryManager.LoginRepository.GetClientLoginAsync(request.PhoneNumber).ConfigureAwait(false);
            ValidateLoginInfo(request, loginInfo);
            
            var principal = _serviceManager.TokenService.GetPrincipalFromToken(request.AccessToken);
            var token = _serviceManager.TokenService.GenerateAccessToken(principal.Claims);

            var refreshToken = _serviceManager.TokenService.GenerateRefreshToken();
            loginInfo.RefreshToken = refreshToken;
            var expiryTime = _serviceManager.Configuration.GetSection("RefreshTokenValidityHours").Value;
            loginInfo.RefreshTokenExpiryTime = int.TryParse(expiryTime, out var time) ?
                DateTime.UtcNow.AddHours(time) :
                throw new ConfigurationParameterNotFound("Config param RefreshTokenValidityHours not found");

            await _repositoryManager.UnitOfWork.SaveChangesAsync().ConfigureAwait(false);

            return new AuthenticatedResponse
            {
                Token = token,
                RefreshToken = refreshToken,
            };
        }

        public async Task<AuthenticatedResponse> SignUp(SignUpRequest request)
        {
            ValidateSignUpRequest(request);
            var loginInfo = await _repositoryManager.LoginRepository.GetClientLoginAsync(request.PhoneNumber).ConfigureAwait(false);

            if (loginInfo == null)
            {
                var registeredUser = new ClientLoginInfo
                {
                    Id = Guid.NewGuid(),
                    PhoneNumber = request.PhoneNumber,
                    PasswordSalt = _serviceManager.PasswordService.GenerateSalt(),
                };

                registeredUser.PasswordHash = _serviceManager.PasswordService.ComputeHash(request.Password, registeredUser.PasswordSalt);

                var claims = GetClaims(request);
                var token = _serviceManager.TokenService.GenerateAccessToken(claims);
                var refreshToken = _serviceManager.TokenService.GenerateRefreshToken();
                registeredUser.RefreshToken = refreshToken;
                var expiryTime = _serviceManager.Configuration.GetSection("RefreshTokenValidityHours").Value;
                registeredUser.RefreshTokenExpiryTime = int.TryParse(expiryTime, out var time) ?
                    DateTime.UtcNow.AddHours(time) :
                    throw new ConfigurationParameterNotFound("Config param RefreshTokenValidityHours not found");

                await _repositoryManager.LoginRepository.InsertAsync(registeredUser).ConfigureAwait(false);
                await _repositoryManager.UnitOfWork.SaveChangesAsync().ConfigureAwait(false);

                return new AuthenticatedResponse
                {
                    Token = token,
                    RefreshToken = refreshToken,
                };
            }

            throw new DuplicateClientLoginInfoException();
        }

        public AuthenticatedResponse Logout(string username)
        {
            throw new NotImplementedException();
        }

        private void ValidateLoginRequest(LoginRequest request)
        {
            if (request is null)
                throw new ArgumentNullException(nameof(request));

            if (string.IsNullOrWhiteSpace(request.PhoneNumber))
                throw new ArgumentNullException("Phone number missed");

            if (string.IsNullOrWhiteSpace(request.AccessToken))
                throw new ArgumentNullException("Access token missed");

            if (string.IsNullOrWhiteSpace(request.RefreshToken))
                throw new ArgumentNullException("Refresh token missed");
        }

        private void ValidateLoginInfo(LoginRequest request, ClientLoginInfo loginInfo)
        {
            if (loginInfo is null)
                throw new UserNotFoundException("User not found");

            var passwordHash = _serviceManager.PasswordService.ComputeHash(request.Password, loginInfo.PasswordSalt);
            if (loginInfo.PasswordHash != passwordHash)
                throw new PasswordHashDoesNotMatch();

            if (loginInfo.RefreshToken != request.RefreshToken)
                throw new RefreshTokenDoesNotMatch();

            if (loginInfo.RefreshTokenExpiryTime <= DateTime.UtcNow)
                throw new RefreshTokentExpiryTimeDoesNotMatchException();

        }

        private void ValidateSignUpRequest(SignUpRequest request)
        {
            if (request is null)
                throw new ArgumentNullException(nameof(request));

            if (string.IsNullOrWhiteSpace(request.PhoneNumber))
                throw new ArgumentNullException("Phone number missed");

            if (string.IsNullOrWhiteSpace(request.Password))
                throw new ArgumentNullException("Password missed");

            if (string.IsNullOrWhiteSpace(request.ClaimType))
                throw new ArgumentNullException("ClaimType missed");
        }

        private List<Claim> GetClaims(SignUpRequest request)
        {
            var claims = new List<Claim>();
            switch (request.ClaimType)
            {
                case "Manager":
                    claims.Add(new Claim(ClaimTypes.Name, "Provider"));
                    claims.Add(new Claim(ClaimTypes.Role, "Provider"));
                    break;
                case "Support":
                    claims.Add(new Claim(ClaimTypes.Name, "Support"));
                    claims.Add(new Claim(ClaimTypes.Role, "Support manager"));
                    break;
                case "Admin":
                    claims.Add(new Claim(ClaimTypes.Name, "Admin"));
                    claims.Add(new Claim(ClaimTypes.Role, "Admin"));
                    break;
                case "Default":
                    claims.Add(new Claim(ClaimTypes.Name, "DefaultClaims"));
                    claims.Add(new Claim(ClaimTypes.Role, "RegularUser"));
                    break;
                default:
                    throw new NotImplementedException("Unknown claim type");
            }
            
            return claims;
        }
    }
}
