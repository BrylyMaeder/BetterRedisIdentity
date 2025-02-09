using BetterRedisIdentity.Util;
using Microsoft.AspNetCore.Identity;
using AsyncRedisDocuments;

namespace BetterRedisIdentity.Data
{
    public class ExternalLoginDocument : IAsyncDocument
    {
        public string Id { get; set; }

        public static ExternalLoginDocument Create(string id)
        {
            return new ExternalLoginDocument { Id = id };
        }

        public static ExternalLoginDocument Create(UserLoginInfo loginInfo) 
        {
            return Create(loginInfo.ToKey());
        }

        public AsyncProperty<UserLoginInfo> LoginInfo => new(this);

        public AsyncLink<RedisIdentityUser> User => new(this);

        public string IndexName()
        {
            return $"identity:logins";
        }
    }
}
