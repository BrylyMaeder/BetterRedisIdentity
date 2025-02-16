using AsyncRedisDocuments;
using AsyncRedisDocuments.Index;
using AsyncRedisDocuments.QueryBuilder;
using Microsoft.AspNetCore.Identity;

namespace BetterRedisIdentity.Stores
{
    public class RedisRoleStore<TRole> : IRoleStore<TRole> where TRole : RedisIdentityRole, new()
    {
        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            if (await role.ExistsAsync())
                return IdentityResult.Failed();

            await role.CreatedDate.SetAsync(DateTime.Now);
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            await role.DeleteAsync();
            return IdentityResult.Success;
        }

        public void Dispose()
        {

        }

        public async Task<TRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            return new TRole { Id = roleId };
        }

        public async Task<TRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            var result = await QueryBuilder.Query<TRole>(s => s.NameNormalized == normalizedRoleName).ToListAsync(1, 1);

            return result.FirstOrDefault();

        }

        public async Task<string?> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            return await role.NameNormalized.GetAsync();
        }

        public async Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            return role.Id;
        }

        public async Task<string?> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            return await role.Name.GetAsync();
        }

        public async Task SetNormalizedRoleNameAsync(TRole role, string? normalizedName, CancellationToken cancellationToken)
        {
            await role.NameNormalized.SetAsync(normalizedName ?? string.Empty);
        }

        public async Task SetRoleNameAsync(TRole role, string? roleName, CancellationToken cancellationToken)
        {
            await role.Name.SetAsync(roleName ?? string.Empty);
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            // nothing to do here
            await Task.CompletedTask;

            return IdentityResult.Success;
        }
    }
}
