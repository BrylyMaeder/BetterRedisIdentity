
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using BetterRedisIdentity.Stores;

namespace BetterRedisIdentity
{
    public static class RedisIdentityStoresExtensions
    {
        public static IServiceCollection AddRedisIdentityStores<TUser, TRole>(this IServiceCollection services)
        where TUser : RedisIdentityUser, new()
        where TRole : RedisIdentityRole, new()
        {
            services.AddScoped<RedisRoleStore<TRole>>();

            services.AddScoped<IUserStore<TUser>>(provider =>
            {
                var roleStore = provider.GetRequiredService<RedisRoleStore<TRole>>();
                return new RedisUserStore<TUser, TRole>(roleStore);
            });

            services.AddScoped<IRoleStore<TRole>, RedisRoleStore<TRole>>();

            // Register the RedisUserManager
            services.AddScoped<UserManager<TUser>, RedisUserManager<TUser>>();

            return services;
        }

    }
}
