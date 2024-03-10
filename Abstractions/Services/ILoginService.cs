namespace Abstractions.Services
{
    using Contracts.RequestResponses;
    using Contracts.Requests;

    public interface ILoginService
    {
        public Task<AuthenticatedResponse> LogIn(LoginRequest loginModel);
        public Task<AuthenticatedResponse> SignUp(SignUpRequest loginModel);
        public AuthenticatedResponse Logout(string username);
    }
}
