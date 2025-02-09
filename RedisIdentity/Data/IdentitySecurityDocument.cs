using AsyncRedisDocuments;

namespace BetterRedisIdentity.Data
{
    public class IdentitySecurityDocument : IAsyncDocument
    {
        public AsyncProperty<bool> LockoutEnabled => new(this);

        public AsyncProperty<int> AccessFailedCount => new(this);

        public AsyncProperty<DateTimeOffset> LockoutEnd => new(this);

        public AsyncProperty<string> PasswordHash => new(this);

        public AsyncLinkSet<IdentityClaimDocument> Claims => new(this);

        public ManagedLinkSet<ExternalLoginDocument> Logins => new(this);

        public AsyncLinkSet<RedisIdentityRole> Roles => new(this);

        public AsyncProperty<string> SecurityStamp => new(this);

        public AsyncProperty<bool> TwoFactorEnabled => new(this);

        public AsyncProperty<string> AuthenticatorKey => new(this);

        public AsyncDictionary<string, string> AuthenticatorTokens => new(this);

        public AsyncList<string> AuthenticatorRecoveryCodes => new(this);

        public string Id { get; set; }

        public string IndexName()
        {
            return "identity:security";
        }
    }
}
