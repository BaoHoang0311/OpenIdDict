using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using SeverIDDictAPI.Data;
using SeverIDDictAPI.Model;
using SeverIDDictAPI.Modelssssssssssssssss;
using System.Security.Claims;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SeverIDDictAPI.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        public HomeController(ApplicationDbContext context)
        {
            _context = context;
        }
        public IActionResult Index()
        {
            return View("~/Views/Home/Index.cshtml");
        }
        public IActionResult Privacy()
        {
            return View("~/Views/Home/Privacy.cshtml");
        }
     
        [HttpGet]
        public async Task<IActionResult> Login(string ReturnUrl)
        {
            var rerrsers = await _context.Users.ToListAsync();
            var model = new LoginModel() { ReturnUrl = ReturnUrl };
            return View("~/Views/Login/Login.cshtml",model );
        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x=>x.UserName == model.UserNameOrEmail && x.Password == model.Password);
            if(user != null)
            {
                if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
                {
                    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);
                    identity.AddClaim(Claims.Email, user.Email);
                    identity.AddClaim(Claims.Subject, user.UserName);
                    identity.AddClaim("id", user.Id);
                    identity.AddClaim(Claims.Username, user.UserName);
                    await HttpContext.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
                    return Redirect(model.ReturnUrl);
                }
                return RedirectToAction("Index", "Home");

            }
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View("~/Views/Login/Login.cshtml", model);
        }
    }
}
