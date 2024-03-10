namespace Services.Tests
{
    using Shouldly;
    using System.Collections.Generic;
    using System.Security.Claims;
    using Microsoft.Extensions.Configuration;
    using Xunit;
    using Abstractions.Services;
    using Moq;
    using Domain.Exceptions;
    using System;

    public class TokenServiceTests
    {
        private const string SecretKey = "vInmMDHz/Qb1CWGkNQ+ijvrC9E6nvbEW0DTMyqU5nTz6ccnrVQ1NCjPZnOZqjEDBgBAiYKGVje+RhsnaeY1iaA==";
        private ITokenService _tokenService;
        private Mock<IConfiguration> _configurationMock;

        public TokenServiceTests()
        {
            _configurationMock = InitConfiguration();
            _tokenService = new TokenService(_configurationMock.Object);
        }

        [Fact]
        public void GenerateAccessToken_ValidClaims_ReturnsValidToken()
        {
            // Arrange
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
            };

            // Act
            var accessToken = _tokenService.GenerateAccessToken(claims);

            // Assert
            accessToken.ShouldNotBeNullOrEmpty();
            accessToken.ShouldNotBeNullOrWhiteSpace();
        }

        [Fact]
        public void GenerateAccessToken_MissedSecretKeyConfigurationParameter_ShouldThrowException()
        {
            // Arrange
            _configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();

            _configurationMock.Setup(x => x.GetSection("JwtTokenSettings"))
                .Returns(tokenSettingsMock.Object);

            tokenSettingsMock.Setup(x => x["SecretKey"]).Returns(string.Empty);

            _tokenService = new TokenService(_configurationMock.Object);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
            };

            // Act
            var exception = Assert.Throws<ConfigurationParameterNotFound>(() => _tokenService.GenerateAccessToken(claims));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Config param SecretKey not found");
        }

        [Fact]
        public void GenerateAccessToken_MissedIssuerConfigurationParameter_ShouldThrowException()
        {
            // Arrange
            _configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();

            _configurationMock.Setup(x => x.GetSection("JwtTokenSettings"))
                .Returns(tokenSettingsMock.Object);

            tokenSettingsMock.Setup(x => x["SecretKey"]).Returns(SecretKey);
            tokenSettingsMock.Setup(x => x["Issuer"]).Returns(string.Empty);

            _tokenService = new TokenService(_configurationMock.Object);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
            };

            // Act
            var exception = Assert.Throws<ConfigurationParameterNotFound>(() => _tokenService.GenerateAccessToken(claims));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Config param Issuer not found");
        }

        [Fact]
        public void GenerateAccessToken_MissedAudienceConfigurationParameter_ShouldThrowException()
        {
            // Arrange
            _configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();

            _configurationMock.Setup(x => x.GetSection("JwtTokenSettings"))
                .Returns(tokenSettingsMock.Object);

            tokenSettingsMock.Setup(x => x["SecretKey"]).Returns(SecretKey);
            tokenSettingsMock.Setup(x => x["Issuer"]).Returns("qw");
            tokenSettingsMock.Setup(x => x["Audience"]).Returns(string.Empty);

            _tokenService = new TokenService(_configurationMock.Object);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
            };

            // Act
            var exception = Assert.Throws<ConfigurationParameterNotFound>(() => _tokenService.GenerateAccessToken(claims));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Config param Audience not found");
        }

        [Fact]
        public void GenerateAccessToken_MissedAccessTokenValidityHoursConfigurationParameter_ShouldThrowException()
        {
            // Arrange
            _configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();

            _configurationMock.Setup(x => x.GetSection("JwtTokenSettings"))
                .Returns(tokenSettingsMock.Object);

            tokenSettingsMock.Setup(x => x["SecretKey"]).Returns(SecretKey);
            tokenSettingsMock.Setup(x => x["Issuer"]).Returns("qw");
            tokenSettingsMock.Setup(x => x["Audience"]).Returns("wq");
            tokenSettingsMock.Setup(x => x["AccessTokenValidityHours"]).Returns(string.Empty);

            _tokenService = new TokenService(_configurationMock.Object);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
            };

            // Act
            var exception = Assert.Throws<ConfigurationParameterNotFound>(() => _tokenService.GenerateAccessToken(claims));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Config param AccessTokenValidityHours not found");
        }

        [Fact]
        public void GenerateRefreshToken_ReturnsValidToken()
        {
            // Act
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Assert
            refreshToken.ShouldNotBeNullOrEmpty();
            refreshToken.ShouldNotBeNullOrWhiteSpace();
            refreshToken.Length.ShouldBe(44);
        }

        [Fact]
        public void GetPrincipalFromToken_ValidToken_ReturnsValidPrincipal()
        {
            // Arrange
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "John Doe"),
            };

            var accessToken = _tokenService.GenerateAccessToken(claims);

            _configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();

            _configurationMock.Setup(x => x.GetSection("JwtTokenSettings"))
                .Returns(tokenSettingsMock.Object);

            tokenSettingsMock.Setup(x => x.GetSection("SecretKey").Value).Returns(SecretKey);
            _tokenService = new TokenService(_configurationMock.Object);

            // Act
            var principal = _tokenService.GetPrincipalFromToken(accessToken);

            // Assert
            principal.ShouldNotBeNull();
            var claimName = principal.FindFirst(ClaimTypes.Name)?.Value;
            claimName.ShouldBe("John Doe");
        }


        [Fact]
        public void GetPrincipalFromToken_EmptyToken_ShouldThrowException()
        {
            // Act
            var exception = Assert.Throws<ArgumentNullException>(() => _tokenService.GetPrincipalFromToken(string.Empty));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Value cannot be null. (Parameter 'Token not transferred')");
        }

        [Fact]
        public void GetPrincipalFromToken_ValidToken_ShouldThrowConfigParamException()
        {
            // Arrange
            _configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();

            _configurationMock.Setup(x => x.GetSection("JwtTokenSettings"))
                .Returns(tokenSettingsMock.Object);

            tokenSettingsMock.Setup(x => x.GetSection("SecretKey").Value).Returns(string.Empty);

            _tokenService = new TokenService(_configurationMock.Object);

            // Act
            var exception = Assert.Throws<ConfigurationParameterNotFound>(() => _tokenService.GetPrincipalFromToken("wq"));

            // Assert
            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Config param SecretKey not found");
        }


        private Mock<IConfiguration> InitConfiguration()
        {
            _configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();

            _configurationMock.Setup(x => x.GetSection("JwtTokenSettings"))
                .Returns(tokenSettingsMock.Object);

            tokenSettingsMock.Setup(x => x["SecretKey"]).Returns(SecretKey);
            tokenSettingsMock.Setup(x => x["Issuer"]).Returns("ew");
            tokenSettingsMock.Setup(x => x["Audience"]).Returns("ew");
            tokenSettingsMock.Setup(x => x["AccessTokenValidityHours"]).Returns("1");

            return _configurationMock;
        }
    }
}