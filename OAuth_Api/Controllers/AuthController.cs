namespace OAuth_Api.Controllers
{
    using Abstractions.Services;
    using Contracts.Requests;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IServiceManager _serviceManager;

        public AuthController(IServiceManager serviceManager)
        {
            _serviceManager = serviceManager;
        }

        [HttpPost, Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var loginResult = await _serviceManager.LoginService.LogIn(request).ConfigureAwait(false);
            return Ok(loginResult);
        }

        [HttpPost, Route("signup")]
        public async Task<IActionResult> SignUp([FromBody] SignUpRequest loginModel)
        {
            var signUpResult = await _serviceManager.LoginService.SignUp(loginModel).ConfigureAwait(false);
            return Ok(signUpResult);
        }

        [HttpPost, Authorize]
        [Route("revoke")]
        public IActionResult Revoke()
        {
            var username = User.Identity.Name;
            _serviceManager.LoginService.Logout(username);
            //var user = _userContext.LoginModels.SingleOrDefault(u => u.UserName == username);
            //if (user == null) return BadRequest();
            //user.RefreshToken = null;
            //_userContext.SaveChanges();
            return NoContent();
        }
    }
}
