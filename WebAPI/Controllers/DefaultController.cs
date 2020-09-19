using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using System.Web.Security;

namespace WebAPI.Controllers
{
    public class DefaultController : ApiController
    {
        [HttpGet]
        public IHttpActionResult Login(string UserName, string Password)
        {
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1, UserName, DateTime.Now, DateTime.Now.AddDays(1), true, $"{UserName}:{Password}");

            string _ticket = FormsAuthentication.Encrypt(ticket);

            HttpRuntime.Cache["User"] = new User { UserName = UserName, Password = Password };

            return Ok<string>(_ticket);
        }
    }

    public class User
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
