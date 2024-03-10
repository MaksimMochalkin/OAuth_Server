namespace Persistence.Repositories
{
    using Abstractions.Repositories;

    public sealed class RepositoryManager : IRepositoryManager
    {
        private readonly Lazy<IUnitOfWork> _lazyUnitOfWork;
        private readonly Lazy<ILoginRepository> _loginRepository;

        public RepositoryManager(RepositoryDbContext dbContext)
        {
            _lazyUnitOfWork = new Lazy<IUnitOfWork>(() => new UnitOfWork(dbContext));
            _loginRepository = new Lazy<ILoginRepository>(() => new LoginRepository(dbContext));
        }

        public IUnitOfWork UnitOfWork => _lazyUnitOfWork.Value;

        public ILoginRepository LoginRepository => _loginRepository.Value;
    }
}
