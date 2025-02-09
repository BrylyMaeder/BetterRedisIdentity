using AsyncRedisDocuments;
using BetterRedisIdentity.Util;
using System.Security.Claims;

namespace BetterRedisIdentity.Data
{
    public class IdentityClaimDocument : IAsyncDocument
    {
        public string Id { get; set; }

        public static IdentityClaimDocument Create(string id)
        {
            return new IdentityClaimDocument() { Id = id };
        }

        public static IdentityClaimDocument Create(Claim claim) 
        {
            return Create(claim.ToKey());
        }

        public string IndexName()
        {
            return "identity:claims";
        }

        public AsyncProperty<Claim> Claim => new(this);

        public AsyncLinkSet<RedisIdentityUser> Users => new(this);
    }
}
