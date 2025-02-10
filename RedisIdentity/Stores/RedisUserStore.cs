using AsyncRedisDocuments;
using AsyncRedisDocuments.Index;
using Microsoft.AspNetCore.Identity;
using BetterRedisIdentity.Data;
using BetterRedisIdentity.Util;
using System.Security.Claims;

namespace BetterRedisIdentity.Stores
{
    public class RedisUserStore<TUser, TRole> : IUserStore<TUser>, IUserEmailStore<TUser>, IUserClaimStore<TUser>, IUserLockoutStore<TUser>, IUserTwoFactorStore<TUser>,
        IUserLoginStore<TUser>, IUserPasswordStore<TUser>, IUserPhoneNumberStore<TUser>, IUserRoleStore<TUser>, IUserSecurityStampStore<TUser>,
        IUserAuthenticatorKeyStore<TUser>, IUserAuthenticationTokenStore<TUser>, IUserTwoFactorRecoveryCodeStore<TUser>
        where TUser : RedisIdentityUser, new() where TRole : RedisIdentityRole, new()
    {
        private readonly RedisRoleStore<TRole> _roleStore;

        public RedisUserStore(RedisRoleStore<TRole> roleStore)
        {
            _roleStore = roleStore ?? throw new ArgumentNullException(nameof(roleStore));
        }

        #region User
        public async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
            return user.Id;
        }

        public async Task<string?> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            return await user.UserName.GetAsync();
        }

        public async Task SetUserNameAsync(TUser user, string? userName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(userName))
                userName = string.Empty;

            await user.UserName.SetAsync(userName);
        }

        public async Task<string?> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            return await user.NormalizedUsername.GetAsync();
        }

        public async Task SetNormalizedUserNameAsync(TUser user, string? normalizedName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(normalizedName))
                normalizedName = string.Empty;

            await user.NormalizedUsername.SetAsync(normalizedName);
        }

        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            //fail to create a user if the username is not set.
            var username = await user.UserName.GetAsync();
            if (string.IsNullOrEmpty(username))
            {
                // Clean up passwords/emails or any other set information before this point.
                await user.DeleteAsync();

                return IdentityResult.Failed();
            }
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            await user.LastUpdate.SetAsync(DateTime.Now);
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            await user.DeleteAsync();
            return IdentityResult.Success;
        }

        public async Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentException("User ID cannot be null, empty, or consist only of whitespace.", nameof(userId));

            var user = DocumentFactory.Create<TUser>(userId) ?? throw new InvalidOperationException("Failed to create a TUser instance.");

            return await user.ExistsAsync() ? user : null;
        }

        public async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(normalizedUserName))
                throw new ArgumentException("User name cannot be null, empty, or consist only of whitespace.", nameof(normalizedUserName));

            var results = await QueryExecutor.Query<TUser>().Tag(s => s.NormalizedUsername, normalizedUserName).SearchAsync();

            if (results == null)
                return null;
            return results.FirstOrDefault();
        }

        public void Dispose()
        {

        }
        #endregion

        #region Email
        public async Task<string> GetEmailAsync(TUser user)
        {
            ArgumentNullException.ThrowIfNull(user);

            var email = await GetEmailAsync(user);
            return email ?? string.Empty;
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            ArgumentNullException.ThrowIfNull(user);

            return await GetEmailConfirmedAsync(user);
        }

        public async Task<TUser> FindByEmailAsync(string email)
        {
            ArgumentNullException.ThrowIfNull(email);

            return await FindByEmailAsync(email) ?? throw new InvalidOperationException("User not found.");
        }

        public async Task SetEmailAsync(TUser user, string? email, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(email);

            await user.Email.SetAsync(email);
        }

        public async Task<string?> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            return await user.Email.GetAsync();
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            return await user.EmailConfirmed.GetAsync();
        }

        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            await user.EmailConfirmed.SetAsync(confirmed);
        }

        public async Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            var users = await QueryExecutor.Query<TUser>().Tag(s => s.Email, normalizedEmail).SearchAsync();
            return users.FirstOrDefault();
        }

        public async Task<string?> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            return await user.NormalizedEmail.GetAsync();
        }

        public async Task SetNormalizedEmailAsync(TUser user, string? normalizedEmail, CancellationToken cancellationToken)
        {
            await user.NormalizedEmail.SetAsync(normalizedEmail ?? throw new Exception("Email cannot be empty!"));
        }

        #endregion

        #region Claims
        public async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(claims);

            foreach (var claim in claims)
            {
                var claimDocument = IdentityClaimDocument.Create(claim);

                await claimDocument.Users.AddOrUpdateAsync(user);
                await user.Security.Document.Claims.AddOrUpdateAsync(claimDocument);
            }
        }


        public async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);

            List<Claim> claims = new List<Claim>();

            var claimDocuments = await user.Security.Document.Claims.GetAllAsync();
            foreach (var claimDoc in claimDocuments)
            {
                claims.Add(await claimDoc.Claim.GetAsync());
            }

            return claims;
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            var claimDocument = IdentityClaimDocument.Create(claim.ToKey());
            var users = await claimDocument.Users.GetAllAsync();

            return (IList<TUser>)users;
        }


        public async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(claim);

            var targetClaim = await user.Security.Document.Claims.GetAsync(claim.ToKey());

            if (targetClaim != null)
            {
                await user.Security.Document.Claims.RemoveAsync(targetClaim.Id);
                await targetClaim.Users.RemoveAsync(claim.ToKey());

                var totalUsers = await targetClaim.Users.CountAsync();
                if (totalUsers == 0)
                    await targetClaim.DeleteAsync();
            }
        }

        public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(claims);

            foreach (var claim in claims)
            {
                await RemoveClaimAsync(user, claim);
            }
        }

        public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(claim);
            ArgumentNullException.ThrowIfNull(newClaim);

            var claimDocument = IdentityClaimDocument.Create(claim);
            await claimDocument.Claim.SetAsync(newClaim);
        }
        #endregion

        #region Lockout
        async Task<int> IUserLockoutStore<TUser>.IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);

            var accessFailedCount = await user.Security.Document.AccessFailedCount.GetAsync();
            var newAccessFailedCount = accessFailedCount + 1;

            await user.Security.Document.AccessFailedCount.SetAsync(newAccessFailedCount);
            return newAccessFailedCount;
        }

        public async Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            await user.Security.Document.AccessFailedCount.SetAsync(0);
        }

        public async Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            return await user.Security.Document.AccessFailedCount.GetAsync();
        }

        public async Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            return await user.Security.Document.LockoutEnabled.GetAsync();
        }

        public async Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            await user.Security.Document.LockoutEnabled.SetAsync(enabled);
        }

        public async Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);

            var lockoutEnd = await user.Security.Document.LockoutEnd.GetAsync();
            return lockoutEnd == default ? null : lockoutEnd;
        }

        public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            await user.Security.Document.LockoutEnd.SetAsync(lockoutEnd ?? default);
        }
        #endregion

        #region Login
        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            ArgumentNullException.ThrowIfNull(login);

            var externalLogin = ExternalLoginDocument.Create(login);

            return (TUser)await externalLogin.User.GetAsync();
        }

        public async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            var externalLogin = ExternalLoginDocument.Create(login);

            await Task.WhenAll(user.Security.Document.Logins.AddOrUpdateAsync(externalLogin),
                externalLogin.User.SetAsync(user),
                externalLogin.LoginInfo.SetAsync(login));
        }

        public async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var key = $"{loginProvider}.{providerKey}";
            var login = ExternalLoginDocument.Create(key);

            await Task.WhenAll(login.DeleteAsync(), user.Security.Document.Logins.RemoveAsync(login.Id));
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            var loginDocuments = await user.Security.Document.Logins.GetAllAsync();

            var loginInfos = new List<UserLoginInfo>();

            foreach (var loginDocument in loginDocuments)
            {
                var loginInfo = await loginDocument.LoginInfo.GetAsync();
                loginInfos.Add(loginInfo);
            }

            return loginInfos;
        }

        public async Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var key = $"{loginProvider}.{providerKey}";
            var login = ExternalLoginDocument.Create(key);

            return (TUser?)await login.User.GetAsync();
        }
        #endregion

        #region Password
        public async Task<string?> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            if (user.Security == null || user.Security.Document.PasswordHash == null)
                throw new InvalidOperationException("PasswordHash is not initialized.");

            return await user.Security.Document.PasswordHash.GetAsync();
        }

        public async Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            if (user.Security == null || user.Security.Document.PasswordHash == null)
                throw new InvalidOperationException("PasswordHash is not initialized.");

            var hash = await user.Security.Document.PasswordHash.GetAsync();
            return !string.IsNullOrEmpty(hash);
        }

        public async Task SetPasswordHashAsync(TUser user, string? passwordHash, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            if (user.Security == null || user.Security.Document.PasswordHash == null)
                throw new InvalidOperationException("PasswordHash is not initialized.");
            if (string.IsNullOrEmpty(passwordHash))
                throw new ArgumentException("Password hash cannot be null or empty.", nameof(passwordHash));

            await user.Security.Document.PasswordHash.SetAsync(passwordHash);
        }
        #endregion

        #region PhoneNumber
        public async Task<string> GetPhoneNumberAsync(TUser user, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(user);
            return await user.PhoneNumber.GetAsync();
        }

        public async Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            return await user.PhoneNumberConfirmed.GetAsync();
        }


        public async Task SetPhoneNumberAsync(TUser user, string? phoneNumber, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);
            if (string.IsNullOrEmpty(phoneNumber)) throw new ArgumentException("Phone number cannot be null or empty.", nameof(phoneNumber));

            await user.PhoneNumber.SetAsync(phoneNumber);
        }

        public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(user);

            await user.PhoneNumberConfirmed.SetAsync(confirmed);
        }
        #endregion

        #region Roles
        public async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Role name cannot be null, empty, or whitespace.", nameof(roleName));

            var normalizedRoleName = roleName.ToUpperInvariant();
            var role = await _roleStore.FindByNameAsync(normalizedRoleName, cancellationToken);
            if (role == null)
                throw new InvalidOperationException($"Role '{roleName}' does not exist.");

            await Task.WhenAll(user.Security.Document.Roles.AddOrUpdateAsync(role), role.Users.AddOrUpdateAsync(user));
        }

        public async Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Role name cannot be null, empty, or whitespace.", nameof(roleName));

            var normalizedRoleName = roleName.ToUpperInvariant();
            var role = await _roleStore.FindByNameAsync(normalizedRoleName, cancellationToken);
            if (role == null)
                throw new InvalidOperationException($"Role '{roleName}' does not exist.");

            await Task.WhenAll(user.Security.Document.Roles.RemoveAsync(role.Id), role.Users.RemoveAsync(user.Id));
        }

        public async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            var roles = await user.Security.Document.Roles.GetAllAsync();
            return roles.Select(role => role.Id).ToList();
        }

        public async Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Role name cannot be null, empty, or whitespace.", nameof(roleName));

            var normalizedRoleName = roleName.ToUpperInvariant();
            var role = await _roleStore.FindByNameAsync(normalizedRoleName, cancellationToken);
            if (role == null) return false;

            return await user.Security.Document.Roles.ContainsAsync(role.Id);
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Role name cannot be null, empty, or whitespace.", nameof(roleName));

            var normalizedRoleName = roleName.ToUpperInvariant();
            var role = await _roleStore.FindByNameAsync(normalizedRoleName, cancellationToken);
            if (role == null)
                throw new InvalidOperationException($"Role '{roleName}' does not exist.");

            return await QueryExecutor.GetAllAsync<TUser>();
        }
        #endregion

        #region Security Stamp
        public async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken token)
        {
            await user.Security.Document.SecurityStamp.SetAsync(stamp);
        }

        public async Task<string> GetSecurityStampAsync(TUser user, CancellationToken token)
        {
            return await user.Security.Document.SecurityStamp.GetAsync();
        }
        #endregion

        #region Two Factor
        public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken token)
        {
            await user.Security.Document.TwoFactorEnabled.SetAsync(enabled);
        }

        public async Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken token)
        {
            return await user.Security.Document.TwoFactorEnabled.GetAsync();
        }
        #endregion

        #region Authenticator Key
        public async Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
        {
            await user.Security.Document.AuthenticatorKey.SetAsync(key);
        }

        public async Task<string?> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
        {
            return await user.Security.Document.AuthenticatorKey.GetAsync();
        }
        #endregion

        #region Authenticator Token Store
        public async Task SetTokenAsync(TUser user, string loginProvider, string name, string? value, CancellationToken cancellationToken)
        {
            // Compose the key
            var tokenKey = $"{loginProvider}:{name}";

            // Set or remove token
            if (value is not null)
            {
                await user.Security.Document.AuthenticatorTokens.SetAsync(tokenKey, value);
            }
            else
            {
                await user.Security.Document.AuthenticatorTokens.RemoveAsync(tokenKey);
            }
        }

        public async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            // Compose the key
            var tokenKey = $"{loginProvider}:{name}";

            // Remove token
            await user.Security.Document.AuthenticatorTokens.RemoveAsync(tokenKey);
        }

        public async Task<string?> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            // Compose the key
            var tokenKey = $"{loginProvider}:{name}";

            // Retrieve token
            return await user.Security.Document.AuthenticatorTokens.GetByKeyAsync(tokenKey);
        }
        #endregion

        #region Two Factor Recovery Code Store

        public async Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
        {
            // Clear existing recovery codes and add new ones
            var recoveryCodesList = user.Security.Document.AuthenticatorRecoveryCodes;
            await recoveryCodesList.SetAsync(recoveryCodes);
        }

        public async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
        {
            // Check if the code exists
            var recoveryCodesList = user.Security.Document.AuthenticatorRecoveryCodes;
            var exists = await recoveryCodesList.ContainsAsync(code);
            if (!exists) return false;

            // Remove the redeemed code
            await recoveryCodesList.RemoveAsync(code);
            return true;
        }

        public async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
        {
            // Return the count of recovery codes
            var recoveryCodesList = user.Security.Document.AuthenticatorRecoveryCodes;
            return await recoveryCodesList.CountAsync();
        }

        #endregion

    }
}
