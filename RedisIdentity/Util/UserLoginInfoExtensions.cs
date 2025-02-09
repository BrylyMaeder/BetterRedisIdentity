using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BetterRedisIdentity.Util
{
    public static class UserLoginInfoExtensions
    {
        public static string ToKey(this UserLoginInfo loginInfo)
        {
            return $"{loginInfo.LoginProvider}.{loginInfo.ProviderKey}";
        }
    }
}
