namespace Domain.Exceptions
{
    public class ConfigurationParameterNotFound : NotFoundException
    {
        public ConfigurationParameterNotFound(string message)
            : base(message)
        {
        }
    }
}
