using AsyncRedisDocuments;
using Microsoft.AspNetCore.Identity;


namespace BetterRedisIdentity
{
    public class RedisIdentityRole : IAsyncDocument
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();

        public static RedisIdentityRole Create(string id)
        {
            return new RedisIdentityRole { Id = id };
        }

        public string IndexName()
        {
            return "identity:roles";
        }

        public AsyncProperty<DateTime> CreatedDate => new(this);

        [Unique]
        public AsyncProperty<string> Name => new(this);

        public AsyncProperty<string> NameNormalized => new(this);

        public AsyncLinkSet<RedisIdentityUser> Users => new(this);
    }
}
