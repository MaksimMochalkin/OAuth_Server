namespace Contracts.Requests
{
    using Newtonsoft.Json;

    public class SignUpRequest
    {
        [JsonProperty("PhoneNumber")]
        public string? PhoneNumber { get; set; }
        [JsonProperty("Password")]
        public string? Password { get; set; }
        [JsonProperty("ClaimType")]
        public string? ClaimType { get; set; }
    }
}
