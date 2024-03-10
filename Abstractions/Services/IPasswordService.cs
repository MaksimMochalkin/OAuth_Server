namespace Abstractions.Services
{
    public interface IPasswordService
    {
        string ComputeHash(string password, string salt);
        string GenerateSalt();
    }
}
