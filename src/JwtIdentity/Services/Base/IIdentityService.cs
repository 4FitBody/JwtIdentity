using JwtIdentity.Models;
using JwtIdentity.Options;

namespace JwtIdentity.Services.Base;

public interface IIdentityService
{
    string GetJwtAccessToken(IEnumerable<string> roles, JwtOptions jwtOptions, User user, string email); 
    Task<bool> ValidateTokenAsync(string accessToken, JwtOptions jwtOptions);
}