namespace Persistence.Repositories
{
    using Abstractions.Repositories;
    using System.Threading;
    using System.Threading.Tasks;

    internal sealed class UnitOfWork : IUnitOfWork
    {
        private readonly RepositoryDbContext _dbContext;

        public UnitOfWork(RepositoryDbContext dbContext) =>
            _dbContext = dbContext;

        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) =>
            _dbContext.SaveChangesAsync(cancellationToken);
    }
}
