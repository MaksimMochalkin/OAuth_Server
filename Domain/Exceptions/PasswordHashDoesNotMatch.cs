namespace Domain.Exceptions
{
    public class PasswordHashDoesNotMatch : Exception
    {
        public PasswordHashDoesNotMatch()
            : base("Password hash does not match")
        {
        }
    }
}
