namespace Domain.Exceptions
{
    public class DuplicateClientLoginInfoException : Exception
    {
        public DuplicateClientLoginInfoException()
            : base("A user with this set of parameters already exists")
        {
        }
    }
}
