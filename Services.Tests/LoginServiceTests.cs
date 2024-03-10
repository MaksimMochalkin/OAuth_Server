namespace Services.Tests
{
    using Abstractions.Repositories;
    using Abstractions.Services;
    using Contracts.Requests;
    using Domain.Entities;
    using Domain.Exceptions;
    using Microsoft.Extensions.Configuration;
    using Moq;
    using Shouldly;
    using System.Security.Claims;

    public class LoginServiceTests
    {
        [Fact]
        public async Task LogIn_ValidRequest_ReturnsAuthenticatedResponse()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();
            var unitOfWorkMock = new Mock<IUnitOfWork>();

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "AccessToken",
                RefreshToken = "RefreshToken",
                Password = "Password",
            };

            var loginInfo = new ClientLoginInfo
            {
                PasswordSalt = "Salt",
                PasswordHash = "Password", // Set a valid password hash for your test
                RefreshToken = "RefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(1),
            };

            var principal = new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
            { new Claim(ClaimTypes.Name, "TestUser"), }));

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(request.PhoneNumber))
                .ReturnsAsync(loginInfo);

            serviceManagerMock.Setup(x =>
            x.PasswordService.ComputeHash(request.Password, loginInfo.PasswordSalt))
                .Returns("Password");

            serviceManagerMock.Setup(x => x.TokenService.GetPrincipalFromToken(request.AccessToken))
                .Returns(principal);

            serviceManagerMock.Setup(x => x.TokenService.GenerateAccessToken(It.IsAny<IEnumerable<Claim>>()))
                .Returns("AccessToken");

            serviceManagerMock.Setup(x => x.TokenService.GenerateRefreshToken())
                .Returns("RefreshToken");

            serviceManagerMock.Setup(x => x.Configuration.GetSection("RefreshTokenValidityHours").Value)
                .Returns("1");

            repositoryManagerMock.Setup(x => x.UnitOfWork).Returns(unitOfWorkMock.Object);
            unitOfWorkMock.Setup(x => x.SaveChangesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(1);

            // Act
            var result = await loginService.LogIn(request).ConfigureAwait(false);

            // Assert
            result.ShouldNotBeNull();
            result.Token.ShouldBe("AccessToken");
            result.RefreshToken.ShouldBe("RefreshToken");
        }

        [Theory]
        [InlineData(null, "AccessToken", "RefreshToken", "Password", "Value cannot be null. (Parameter 'Phone number missed')")]
        [InlineData("123456789", null, "RefreshToken", "Password", "Value cannot be null. (Parameter 'Access token missed')")]
        [InlineData("123456789", "AccessToken", null, "Password", "Value cannot be null. (Parameter 'Refresh token missed')")]
        public async Task LogIn_InvalidRequest_ThrowsArgumentException(
            string phoneNumber, string accessToken, string refreshToken,
            string password, string expectedErrorMessage)
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = phoneNumber,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                Password = password,
            };

            // Act
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(() => loginService.LogIn(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe(expectedErrorMessage);
        }

        [Fact]
        public async Task LogIn_RequestIsNull_ThrowsArgumentException()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            // Act
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(() => loginService.LogIn(null));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Value cannot be null. (Parameter 'request')");
        }

        [Fact]
        public async Task LogIn_UserNotFound_ThrowsUserNotFoundException()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var yourClass = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "YourAccessToken",
                RefreshToken = "YourRefreshToken",
                Password = "YourPassword",
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(request.PhoneNumber))
                .ReturnsAsync((ClientLoginInfo)null);

            // Act
            var exception = await Assert.ThrowsAsync<UserNotFoundException>(() => yourClass.LogIn(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("User not found");
        }

        [Fact]
        public async Task LogIn_PasswordHashDoesNotMatch_ThrowsPasswordHashDoesNotMatch()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var yourClass = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "YourAccessToken",
                RefreshToken = "YourRefreshToken",
                Password = "InvalidPassword", // Set an invalid password for your test
            };

            var loginInfo = new ClientLoginInfo
            {
                PasswordSalt = "YourSalt",
                PasswordHash = "YourCorrectPasswordHash", // Set a valid password hash for your test
                RefreshToken = "YourRefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(1),
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(request.PhoneNumber))
                .ReturnsAsync(loginInfo);

            // Act and Assert
            await Assert.ThrowsAsync<PasswordHashDoesNotMatch>(() => yourClass.LogIn(request));
        }

        [Fact]
        public async Task LogIn_RefreshTokenExpired_ThrowsRefreshTokenDoesNotMatch()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var yourClass = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "YourAccessToken",
                RefreshToken = "YourRefreshToken",
                Password = "YourPassword",
            };

            var loginInfo = new ClientLoginInfo
            {
                PasswordSalt = "YourSalt",
                PasswordHash = "YourCorrectPasswordHash", // Set a valid password hash for your test
                RefreshToken = "YourRefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(-1), // Set an expired refresh token
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(request.PhoneNumber))
                .ReturnsAsync(loginInfo);

            // Act and Assert
            await Assert.ThrowsAsync<RefreshTokenDoesNotMatch>(() => yourClass.LogIn(request));
        }

        [Fact]
        public async Task LogIn_RefreshTokenValidityHoursNotConfigured_ThrowsConfigurationParameterNotFound()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();
            var configurationMock = new Mock<IConfiguration>();

            var yourClass = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "YourAccessToken",
                RefreshToken = "YourRefreshToken",
                Password = "YourPassword",
            };

            var loginInfo = new ClientLoginInfo
            {
                PasswordSalt = "YourSalt",
                PasswordHash = "YourCorrectPasswordHash", // Set a valid password hash for your test
                RefreshToken = "YourRefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(1),
                // Set other properties as needed for your test
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(request.PhoneNumber))
                .ReturnsAsync(loginInfo);

            serviceManagerMock.Setup(x => x.TokenService.GetPrincipalFromToken(request.AccessToken))
                .Returns(new ClaimsPrincipal(new ClaimsIdentity(new Claim[0])));

            serviceManagerMock.Setup(x => x.TokenService.GenerateAccessToken(It.IsAny<IEnumerable<Claim>>()))
                .Returns("YourGeneratedAccessToken");

            serviceManagerMock.Setup(x => x.TokenService.GenerateRefreshToken())
                .Returns("YourGeneratedRefreshToken");

            configurationMock.Setup(x => x.GetSection("RefreshTokenValidityHours").Value)
                .Returns(string.Empty); // Simulate missing configuration

            serviceManagerMock.Setup(x => x.Configuration).Returns(configurationMock.Object);

            // Act and Assert
            await Assert.ThrowsAsync<ConfigurationParameterNotFound>(() => yourClass.LogIn(request));
        }
    }
}
