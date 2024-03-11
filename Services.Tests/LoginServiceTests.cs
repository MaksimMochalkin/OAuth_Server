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

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "AccessToken",
                RefreshToken = "RefreshToken",
                Password = "Password",
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(It.IsAny<string>()))
                .ReturnsAsync((ClientLoginInfo)null);

            // Act
            var exception = await Assert.ThrowsAsync<UserNotFoundException>(() => loginService.LogIn(request));

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

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "AccessToken",
                RefreshToken = "RefreshToken",
                Password = "InvalidPassword",
            };

            var loginInfo = new ClientLoginInfo
            {
                PasswordSalt = "Salt",
                PasswordHash = "CorrectPasswordHash",
                RefreshToken = "RefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(1),
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(It.IsAny<string>()))
                .ReturnsAsync(loginInfo);
            serviceManagerMock.Setup(x => x.PasswordService.ComputeHash(It.IsAny<string>(), It.IsAny<string>()))
                .Returns("InvalidPasswordHash");

            // Act
            var exception = await Assert.ThrowsAsync<PasswordHashDoesNotMatch>(() => loginService.LogIn(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Password hash does not match");
        }

        [Fact]
        public async Task LogIn_RefreshTokenExpired_ThrowsRefreshTokenDoesNotMatch()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new LoginRequest
            {
                PhoneNumber = "123456789",
                AccessToken = "AccessToken",
                RefreshToken = "InvalidRefreshToken",
                Password = "Password",
            };

            var loginInfo = new ClientLoginInfo
            {
                PasswordSalt = "YourSalt",
                PasswordHash = "ValidPasswordHash",
                RefreshToken = "RefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(-1),
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(It.IsAny<string>()))
                .ReturnsAsync(loginInfo);
            serviceManagerMock.Setup(x => x.PasswordService.ComputeHash(It.IsAny<string>(), It.IsAny<string>()))
                .Returns("ValidPasswordHash");

            // Act
            var exception = await Assert.ThrowsAsync<RefreshTokenDoesNotMatch>(() => loginService.LogIn(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Refresh tokens does not match");
        }

        [Fact]
        public async Task LogIn_RefreshTokenTimeExpired_ThrowsRefreshTokenDoesNotMatch()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

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
                PasswordSalt = "YourSalt",
                PasswordHash = "ValidPasswordHash",
                RefreshToken = "RefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(-1),
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(It.IsAny<string>()))
                .ReturnsAsync(loginInfo);
            serviceManagerMock.Setup(x => x.PasswordService.ComputeHash(It.IsAny<string>(), It.IsAny<string>()))
                .Returns("ValidPasswordHash");

            // Act
            var exception = await Assert.ThrowsAsync<RefreshTokentExpiryTimeDoesNotMatchException>(() => loginService.LogIn(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Refresh tokent expiry time does not match");
        }

        [Fact]
        public async Task LogIn_RefreshTokenValidityHoursNotConfigured_ThrowsConfigurationParameterNotFound()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();
            var configurationMock = new Mock<IConfiguration>();

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
                PasswordHash = "ValidPasswordHash",
                RefreshToken = "RefreshToken",
                RefreshTokenExpiryTime = DateTime.UtcNow.AddHours(1),
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(It.IsAny<string>()))
                .ReturnsAsync(loginInfo);

            serviceManagerMock.Setup(x => x.PasswordService.ComputeHash(It.IsAny<string>(), It.IsAny<string>()))
                .Returns("ValidPasswordHash");

            serviceManagerMock.Setup(x => x.TokenService.GetPrincipalFromToken(It.IsAny<string>()))
                .Returns(new ClaimsPrincipal(new ClaimsIdentity(new Claim[0])));

            serviceManagerMock.Setup(x => x.TokenService.GenerateAccessToken(It.IsAny<IEnumerable<Claim>>()))
                .Returns("GeneratedAccessToken");

            serviceManagerMock.Setup(x => x.TokenService.GenerateRefreshToken())
                .Returns("GeneratedRefreshToken");

            configurationMock.Setup(x => x.GetSection("RefreshTokenValidityHours").Value)
                .Returns(string.Empty);

            serviceManagerMock.Setup(x => x.Configuration).Returns(configurationMock.Object);

            // Act
            var exception = await Assert.ThrowsAsync<ConfigurationParameterNotFound>(() => loginService.LogIn(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Config param RefreshTokenValidityHours not found");
        }

        [Fact]
        public async Task SignUp_NewUser_SuccessfullyRegistersAndReturnsAuthenticatedResponse()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();
            var unitOfWorkMock = new Mock<IUnitOfWork>();

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new SignUpRequest
            {
                PhoneNumber = "123456789",
                Password = "Password",
                ClaimType = "Manager",
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(request.PhoneNumber))
                .ReturnsAsync((ClientLoginInfo)null);

            serviceManagerMock.Setup(x => x.PasswordService.GenerateSalt())
                .Returns("YourGeneratedSalt");

            serviceManagerMock.Setup(x => x.PasswordService.ComputeHash(request.Password, "YourGeneratedSalt"))
                .Returns("YourGeneratedPasswordHash");

            serviceManagerMock.Setup(x => x.TokenService.GenerateAccessToken(It.IsAny<IEnumerable<Claim>>()))
                .Returns("GeneratedAccessToken");

            serviceManagerMock.Setup(x => x.TokenService.GenerateRefreshToken())
                .Returns("GeneratedRefreshToken");

            serviceManagerMock.Setup(x => x.Configuration.GetSection("RefreshTokenValidityHours").Value)
                .Returns("1");

            repositoryManagerMock.Setup(x => x.LoginRepository.InsertAsync(It.IsAny<ClientLoginInfo>()))
                .Callback<ClientLoginInfo>(user =>
                {
                    user.ShouldNotBeNull();
                    user.PhoneNumber.ShouldBe("123456789");
                })
                .Returns(Task.CompletedTask);

            repositoryManagerMock.Setup(x => x.UnitOfWork).Returns(unitOfWorkMock.Object);
            unitOfWorkMock.Setup(x => x.SaveChangesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(1);

            // Act
            var result = await loginService.SignUp(request);

            // Assert
            result.ShouldNotBeNull();
            result.Token.ShouldNotBeNull();
            result.Token.ShouldBe("GeneratedAccessToken");
            result.RefreshToken.ShouldNotBeNull();
            result.RefreshToken.ShouldBe("GeneratedRefreshToken");
        }

        [Fact]
        public async Task SignUp_ExistingUser_ThrowsDuplicateClientLoginInfoException()
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new SignUpRequest
            {
                PhoneNumber = "123456789",
                Password = "Password",
                ClaimType = "Manager",
            };

            repositoryManagerMock.Setup(x => x.LoginRepository.GetClientLoginAsync(It.IsAny<string>()))
                .ReturnsAsync(new ClientLoginInfo());

            // Act 
            var exception = await Assert.ThrowsAsync<DuplicateClientLoginInfoException>(() => loginService.SignUp(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("A user with this set of parameters already exists");
        }

        [Theory]
        [InlineData(null, "Password", "Manager", "Value cannot be null. (Parameter 'Phone number missed')")]
        [InlineData("123456789", null, "Manager", "Value cannot be null. (Parameter 'Password missed')")]
        [InlineData("123456789", "Password", null, "Value cannot be null. (Parameter 'ClaimType missed')")]
        public async Task SignUp_InvalidRequest_ThrowsArgumentException(
            string phoneNumber, string password, string claimType, string expectedErrorMessage)
        {
            // Arrange
            var repositoryManagerMock = new Mock<IRepositoryManager>();
            var serviceManagerMock = new Mock<IServiceManager>();

            var loginService = new LoginService(repositoryManagerMock.Object, serviceManagerMock.Object);

            var request = new SignUpRequest
            {
                PhoneNumber = phoneNumber,
                Password = password,
                ClaimType = claimType,
            };

            // Act
            var exception = await Assert.ThrowsAsync<ArgumentNullException>(() => loginService.SignUp(request));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe(expectedErrorMessage);
        }
    }
}
