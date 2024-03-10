namespace Abstractions.Repositories
{
    using Domain.Entities;

    public interface ILoginRepository
    {
        public Task<ClientLoginInfo> GetClientLoginAsync(string phoneNumber);

        public Task InsertAsync(ClientLoginInfo entity);

        public Task InsertRangeAsync(IEnumerable<ClientLoginInfo> entities);

        //public Task UpdateAsync(ClientLogin entity);

        //public Task UpdateRangeAsync(IEnumerable<ClientLogin> entities);

        public void RemoveAsync(ClientLoginInfo entity);

        public void RemoveRangeAsync(IEnumerable<ClientLoginInfo> entities);

    }
}
