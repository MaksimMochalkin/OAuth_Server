namespace Persistence.Repositories
{
    using Abstractions.Repositories;
    using Domain.Entities;
    using Microsoft.EntityFrameworkCore;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    internal sealed class LoginRepository : ILoginRepository
    {
        private readonly RepositoryDbContext _dbContext;

        public LoginRepository(RepositoryDbContext dbContext) => _dbContext = dbContext;

        public async Task<ClientLoginInfo> GetClientLoginAsync(string phoneNumber) =>
           await _dbContext.LoginInfos
            .FirstOrDefaultAsync(login => login.PhoneNumber == phoneNumber).ConfigureAwait(false);

        public async Task InsertAsync(ClientLoginInfo entity) =>
            await _dbContext.LoginInfos.AddAsync(entity);

        public async Task InsertRangeAsync(IEnumerable<ClientLoginInfo> entities) =>
            await _dbContext.LoginInfos.AddRangeAsync(entities);

        public void RemoveAsync(ClientLoginInfo entity) =>
            _dbContext.LoginInfos.Remove(entity);

        public void RemoveRangeAsync(IEnumerable<ClientLoginInfo> entities) =>
            _dbContext.LoginInfos.RemoveRange(entities);

        //public Task UpdateAsync(ClientLogin entity) =>
        //    _dbContext.Update();

        //public Task UpdateRangeAsync(IEnumerable<ClientLogin> entities)
        //{
        //    throw new NotImplementedException();
        //}
    }
}
