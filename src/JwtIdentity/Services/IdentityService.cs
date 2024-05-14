using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JwtIdentity.Models;
using JwtIdentity.Options;
using JwtIdentity.Services.Base;
using Microsoft.IdentityModel.Tokens;

namespace JwtIdentity.Services;

public class IdentityService : IIdentityService
{
    public string GetJwtAccessToken(IEnumerable<string> roles, JwtOptions jwtOptions, User user, string email)
    {
        var claims = roles
            .Select(role => new Claim(ClaimTypes.Role, role))
            .Append(new Claim(ClaimTypes.Email, email))
            .Append(new Claim(ClaimTypes.Name, user.UserName!))
            .Append(new Claim(ClaimTypes.Surname, user.Surname!))
            .Append(new Claim("Age", user.Age.ToString()!))
            .Append(new Claim(ClaimTypes.NameIdentifier, user.Id));

        var securityKey = new SymmetricSecurityKey(jwtOptions.KeyInBytes);

        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var securityToken = new JwtSecurityToken(
            issuer: jwtOptions.Issuers.First(),
            audience: jwtOptions.Audience,
            claims,
            expires: DateTime.Now.AddMinutes(jwtOptions.LifetimeInMinutes),
            signingCredentials: signingCredentials
        );

        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        var jwt = jwtSecurityTokenHandler.WriteToken(securityToken);

        return jwt!;
    }

    public async Task<bool> ValidateTokenAsync(string accessToken, JwtOptions jwtOptions)
    {
        var handler = new JwtSecurityTokenHandler();

        var validationResult = await handler.ValidateTokenAsync(
            accessToken,

            new TokenValidationParameters()
            {
                ValidateLifetime = false,
                IssuerSigningKey = new SymmetricSecurityKey(jwtOptions.KeyInBytes),

                ValidateAudience = true,
                ValidAudience = jwtOptions.Audience,

                ValidateIssuer = true,
                ValidIssuers = jwtOptions.Issuers,
            }
        );

        return validationResult.IsValid;
    }
}