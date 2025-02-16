
using AsyncRedisDocuments;
using BetterRedisIdentity.Data;


namespace BetterRedisIdentity
{
    public class RedisIdentityUser : IAsyncDocument
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [Unique]
        public AsyncProperty<string> UserName => new(this);
        [Unique]
        public AsyncProperty<string> NormalizedUsername => new(this);
        [Unique]
        public AsyncProperty<string> Email => new(this);
        [Unique]
        public AsyncProperty<string> NormalizedEmail => new(this);

        public AsyncProperty<bool> EmailConfirmed => new(this);

        [Indexed]
        public AsyncProperty<string> PhoneNumber => new(this);
        public AsyncProperty<bool> PhoneNumberConfirmed => new(this);

        public StaticLink<IdentitySecurityDocument> Security => new(this);

        public AsyncProperty<DateTime> CreationDate => new(this);
        public AsyncProperty<DateTime> LastUpdate => new(this);

        public string IndexName()
        {
            return "identity:users";
        }
    }
}
