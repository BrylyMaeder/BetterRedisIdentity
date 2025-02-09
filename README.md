# Better Redis Identity
**While there are currently several projects available to connect and interface with Redis, I have found that they are not fully implemented/lack support or have critical bugs that make them unreliable.**


## 🧐 Features    
- All user and role stores are implemented.
- Built upon AsyncRedisDocuments (https://github.com/BrylyMaeder/AsyncRedisDocuments)
- Works out of the box
        

## 🛠️ Install Dependencies    
```bash
nuget install BetterRedisIdentity
```

**This will only work for a Redis Database that has Redis Search activated.**

## Important Information
Please review [AsyncRedisDocuments](https://github.com/BrylyMaeder/AsyncRedisDocuments) to ensure you're familiar with how the ApplicationUser and ApplicationRole is expected to work. They are both IAsyncDocuments.

The following security information has moved from the user class to the user Security class, which can be accessed in the following manner:

```csharp
await User.Security.Document.Roles.GetAsync();
```

- LockoutEnabled
- AccessFailedCount
- LockoutEnd
- PasswordHash
- Claims
- Logins
- Roles
- SecurityStamp
- TwoFactorEnabled
- AuthenticatorKey
- AuthenticatorTokens
- AuthenticatorRecoveryCodes

## 🧑🏻‍💻 Setup and Installation
First and and most importantly; initialize your redis singleton.

```csharp
RedisSingleton.Initialize("host", port, "password");
```
Make sure your `ApplicationUser` enherits from `RedisIdentityUser` and your ApplicationRole inherits from `RedisIdentityRole`

```csharp
    public class ApplicationUser : RedisIdentityUser
```
```csharp
    public class ApplicationRole : RedisIdentityRole
```

Next up, add your stores. 

```csharp
builder.Services.AddRedisIdentityStores<ApplicationUser, ApplicationRole>();
```

If you need to use a custom user manager for your project, please ensure that you enherit from 
`RedisUserManager<TUser>` Our manager is necessary and is automatically included with `AddRedisIdentityStores()`


Setup your identity how you like.
```csharp
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.User.RequireUniqueEmail = true;

}).AddDefaultTokenProviders() 
    .AddSignInManager(); 
```

Everything else forwards is pretty standard, include your authentication scheme and you should be all set.
```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.BearerScheme;
    options.DefaultSignInScheme = IdentityConstants.BearerScheme;
}).AddBearerToken();
```


##  Author
#### Bryly Maeder
- Github: https://github.com/BrylyMaeder
        