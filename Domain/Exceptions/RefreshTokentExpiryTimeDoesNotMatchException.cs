namespace Domain.Exceptions
{
    public class RefreshTokentExpiryTimeDoesNotMatchException : Exception
    {
        public RefreshTokentExpiryTimeDoesNotMatchException()
            : base("Refresh tokent expiry time does not match")
        {
        }
    }
}
