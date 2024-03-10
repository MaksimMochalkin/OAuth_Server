namespace Domain.Entities
{
    public class ClientLoginInfo : BaseEntity
    {
        public string? PhoneNumber { get; set; }
        public string? PasswordSalt { get; set; }
        public string? PasswordHash { get; set; }
        public string? RefreshToken { get; set; }
        public string? AccessToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
