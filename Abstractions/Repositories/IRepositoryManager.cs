namespace Abstractions.Repositories
{
    public interface IRepositoryManager
    {
        public IUnitOfWork UnitOfWork { get; }
        public ILoginRepository LoginRepository { get; }

    }
}
