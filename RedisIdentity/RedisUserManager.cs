﻿using AsyncRedisDocuments;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BetterRedisIdentity
{
    public class RedisUserManager<TUser> : UserManager<TUser> where TUser : RedisIdentityUser, new()
    {
        public RedisUserManager(IUserStore<TUser> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<TUser> passwordHasher, IEnumerable<IUserValidator<TUser>> userValidators, IEnumerable<IPasswordValidator<TUser>> passwordValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<TUser>> logger) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public override async Task<IdentityResult> CreateAsync(TUser user)
        {
            var result = await VerifyUserDocument(user);
            if (!result.Succeeded)
            {
                await user.DeleteAsync();
                return result;
            }

            result = await base.CreateAsync(user);
            if (!result.Succeeded)
                await user.DeleteAsync();
            return result;
        }

        public override async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            var result = await base.CreateAsync(user, password);
            if (!result.Succeeded)
                await user.DeleteAsync();
            return result;
        }


        private async Task<IdentityResult> VerifyUserDocument(TUser user) 
        {
            // Since we do not allow duplicate usernames or emails to be set, they should be null here if taken
            // Handle this case and prevent creation, then return a friendly message.

            var username = await user.UserName.GetAsync();
            if (string.IsNullOrEmpty(username))
            {
                var error = new IdentityError
                {
                    Code = "DuplicateUsername",
                    Description = "That username is not available."
                };

                return IdentityResult.Failed(error);
            }

            if (Options.User.RequireUniqueEmail)
            {
                var email = await user.Email.GetAsync();
                if (string.IsNullOrEmpty(email))
                {
                    var error = new IdentityError
                    {
                        Code = "DuplicateEmail",
                        Description = "That email is not available."
                    };

                    return IdentityResult.Failed(error);
                }
            }

            return IdentityResult.Success;
        }
    }
}
