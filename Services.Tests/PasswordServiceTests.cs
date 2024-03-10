namespace Services.Tests
{
    using Domain.Exceptions;
    using Microsoft.Extensions.Configuration;
    using Moq;
    using Shouldly;

    public class PasswordServiceTests
    {
        [Fact]
        public void PasswordService_ShouldReturnPassword()
        {
            // Arrange
            var configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();
            configurationMock.Setup(x => x.GetSection("PasswordPaper").Value).Returns("PasswordPaper");

            var passwordService = new PasswordService(configurationMock.Object);

            // Act
            var result = passwordService.ComputeHash("password", "salt");

            // Assert
            result.ShouldNotBeNullOrWhiteSpace();
            result.ShouldBe("pyzZMskzC5D21GWUKnFhL4gahbPWrUMxnGDHF3LCdOE=");
        }

        [Fact]
        public void PasswordService_PaperNotFound_ShouldThrowException()
        {
            // Arrange
            var configurationMock = new Mock<IConfiguration>();
            var tokenSettingsMock = new Mock<IConfigurationSection>();
            configurationMock.Setup(x => x.GetSection("PasswordPaper").Value).Returns(string.Empty);
            var passwordService = new PasswordService(configurationMock.Object);

            // Act
            var exception = Assert.Throws<ConfigurationParameterNotFound>(() => passwordService.ComputeHash("password", "salt"));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe("Config param PasswordPaper not found");

        }

        [Theory]
        [InlineData(null, "salt", "Value cannot be null. (Parameter 'Password did not transferred')")]
        [InlineData("", "salt", "Value cannot be null. (Parameter 'Password did not transferred')")]
        [InlineData("password", null, "Value cannot be null. (Parameter 'Salt did not transferred')")]
        [InlineData("password", "", "Value cannot be null. (Parameter 'Salt did not transferred')")]
        public void PasswordService_InvalidArguments_ThrowsArgumentException(string password, string salt, string expectedErrorMessage)
        {
            // Arrange
            var configurationMock = new Mock<IConfiguration>();
            var passwordService = new PasswordService(configurationMock.Object);

            // Act
            var exception = Assert.Throws<ArgumentNullException>(() => passwordService.ComputeHash(password, salt));

            // Assert
            exception.ShouldNotBeNull();
            exception.Message.ShouldBe(expectedErrorMessage);
        }

        [Fact]
        public void PasswordService_GenerateSalt_ShouldReturnValue()
        {
            // Arrange
            var configurationMock = new Mock<IConfiguration>();
            var passwordService = new PasswordService(configurationMock.Object);

            // Act
            var result = passwordService.GenerateSalt();

            // Assert
            result.ShouldNotBeNullOrWhiteSpace();
        }
    }
}
