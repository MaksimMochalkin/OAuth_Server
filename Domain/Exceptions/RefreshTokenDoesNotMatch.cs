namespace Domain.Exceptions
{
    public class RefreshTokenDoesNotMatch : Exception
    {
        public RefreshTokenDoesNotMatch()
            : base("Refresh tokens does not match")
        {            
        }
    }
}
