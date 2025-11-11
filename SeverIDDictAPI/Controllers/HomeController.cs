using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Server.AspNetCore;
using SeverIDDictAPI.Data;
using SeverIDDictAPI.Model;
using System.Security.Claims;
using System.Threading.Tasks;

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
            if(model.UserNameOrEmail == "bao" && model.Password == "1234")
            {
                if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
                {
                    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);
                    await HttpContext.SignInAsync(".MyApp.Auth", principal);
                    return Redirect(model.ReturnUrl);
                }
                return RedirectToAction("Index", "Home");

            }
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View("~/Views/Login/Login.cshtml", model);
        }
    }
}
