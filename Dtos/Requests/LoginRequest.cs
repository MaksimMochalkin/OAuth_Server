namespace Contracts.Requests
{
    using Newtonsoft.Json;

    public class LoginRequest
    {
        [JsonProperty("PhoneNumber")]
        public string? PhoneNumber { get; set; }
        public string? PasswordSalt { get; set; }

        [JsonProperty("Password")]
        public string? Password { get; set; }
        
        [JsonProperty("RefreshToken")]
        public string? RefreshToken { get; set; }

        [JsonProperty("AccessToken")]
        public string? AccessToken { get; set; }

        [JsonProperty("RefreshTokenExpiryTime")]
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
