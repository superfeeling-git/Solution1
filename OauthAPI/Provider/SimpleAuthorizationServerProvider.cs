using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace OauthAPI.Provider
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            await Task.Factory.StartNew(() => context.Validated());
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            await Task.Factory.StartNew(() => context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" }));

            try
            {
                var userName = context.UserName;
                var password = context.Password;
                Users user = await Task.Factory.StartNew(() => new Users { UserName = userName, Password = password });
                if (user == null)
                {
                    context.SetError("invalid_grant", "用户名或密码错误");
                    return;
                }
                else
                {
                    var oAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
                    oAuthIdentity.AddClaim(new Claim("sub", context.UserName));
                    oAuthIdentity.AddClaim(new Claim("role", "user"));
                    oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                    oAuthIdentity.AddClaim(new Claim(ClaimTypes.UserData, user.UserID.ToString()));
                    var authenticationProperties = new AuthenticationProperties();
                    var ticket = new AuthenticationTicket(oAuthIdentity, authenticationProperties);
                    context.Validated(ticket);
                }
            }
            catch (System.Exception ex)
            {

                throw;
            }


        }
    }

    public class Users
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public int UserID { get; set; }
    }
}