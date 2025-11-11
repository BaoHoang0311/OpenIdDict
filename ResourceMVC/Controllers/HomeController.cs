using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using ResourceMVC.Models;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace ResourceMVC.Controllers
{
    public class Token
    {
        public string refresh_token { get;set;}
        public string access_token { get;set; }
    }
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Index()
        {
            return View();
        }
        [Authorize]
        public IActionResult Index1()
        {
            var token = HttpContext.Session.GetString("Token");
            ViewBag.Token = token; // đưa sang View
            return View("~/Views/Home/Index1.cshtml");
        }
        public IActionResult AccessDenied()
        {
            return View();
        }
        public async Task<IActionResult> Privacy(string code,string state)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var parameters = new Dictionary<string, string>
            {   
                { "grant_type", "authorization_code" },                                                                                                                                                                                                           
                { "client_id", "test_client" },
                { "code", code }, // Replace with actual code
            };
            var content = new FormUrlEncodedContent(parameters);
            var response = await httpClient.PostAsync("https://localhost:7293/connect/token", content);
            // Read and output the response
            var responseContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseContent);

            var token = JsonSerializer.Deserialize<Token>(responseContent);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token.access_token);
            var identity = new ClaimsIdentity("Application");
            identity.AddClaim(new Claim("Email", jwt.Claims.FirstOrDefault(u => u.Type == "email").Value)); // jwt.Payload["Name"]
            identity.AddClaim(new Claim("Name", jwt.Claims.FirstOrDefault(u => u.Type == "userid").Value)); // jwt.Payload["Name"]
            foreach (var role in jwt.Claims.Where(u => u.Type == "role"))
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, role.Value.ToString()));
            }

            //Claim Pricipal
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync("Application", principal);
            // Lưu token để View có thể dùng (session hoặc TempData)
            HttpContext.Session.SetString("Token", responseContent);
            // redirect sang Privacy để user thấy kết quả
            return RedirectToAction("Index1");
        }
        public IActionResult LoginwithServer()
        {
            var scope = Uri.EscapeDataString("email offline_access profile api.write");
            return Redirect($"https://localhost:7293/connect/authorize?" +
                $"client_id=test_client" +
                $"&response_type=code" +
                $"&state=af0ifjsldkj" +
                $"&redirect_uri=https://localhost:7224/Home/Privacy" +
                $"&scope={scope}");
        }
        public async Task<IActionResult> LogOut()
        {
            await HttpContext.SignOutAsync("Application");
            return RedirectToAction("Index","Home");
        }
    }
}
