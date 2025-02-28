﻿
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using BetterRedisIdentity.Stores;
using BetterRedisIdentity.Services;
using Microsoft.AspNetCore.DataProtection;

namespace BetterRedisIdentity
{
    public static class RedisIdentityStoresExtensions
    {
        public static IServiceCollection AddRedisIdentityStores<TUser, TRole>(this IServiceCollection services, bool provideUserService = true)
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

            // Register optional user service
            if (provideUserService)
                services.AddScoped<UserService<TUser>>();

            return services;
        }
    }
}
