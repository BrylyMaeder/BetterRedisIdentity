
using AsyncRedisDocuments;
using BetterRedisIdentity.Data;


namespace BetterRedisIdentity
{
    public class RedisIdentityUser : IAsyncDocument
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();

        public UniqueProperty<string> UserName => new(this);
        public UniqueProperty<string> NormalizedUsername => new(this);

        public UniqueProperty<string> Email => new(this);
        public UniqueProperty<string> NormalizedEmail => new(this);

        public AsyncProperty<bool> EmailConfirmed => new(this);

        public IndexedProperty<string> PhoneNumber => new(this);
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
