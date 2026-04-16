using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ResourceAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private readonly ApplicationDbContext context;
        public WeatherForecastController(ApplicationDbContext _context)
        {
            context = _context;
        }
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        #region Save Transaction
        [HttpGet("TestTransaction")]
        public async Task<IActionResult> TestTransaction()
        {
            // Sử dụng chiến lược thực thi (Execution Strategy) nếu bạn dùng Azure SQL hoặc có cơ chế retry
            using (var transaction = context.Database.BeginTransaction())
            {
                try
                {
                    var ammount = 5;
                    // 1. Tìm tài khoản A và trừ tiền
                    await UpdateAmountUserA(ammount);


                    await UpdateAmountUserB(ammount);

                    // 4. Xác nhận hoàn tất giao dịch
                    transaction.Commit();
                    Console.WriteLine("Giao dịch thành công!");
                }
                catch (Exception ex)
                {
                    // 5. Nếu có lỗi, Rollback sẽ đưa mọi thứ về trạng thái ban đầu
                    transaction.Rollback();
                    Console.WriteLine($"Giao dịch thất bại: {ex.Message}. Tiền đã được trả lại cho A.");
                }
            }
            return Ok();
        }
        private async Task UpdateAmountUserA(int ammount)
        {
            // 1. Tìm tài khoản A và trừ tiền
            var accountA = context.Users.Find(1);
            if (accountA == null || accountA.Amount < ammount)
                throw new Exception("Tài khoản A không tồn tại hoặc không đủ số dư.");

            accountA.Amount -= ammount;
            context.Update(accountA);
            context.SaveChanges();

            // 3. Lưu thay đổi xuống Database
            // Nếu lệnh này lỗi, nó sẽ nhảy xuống catch
            var accountC = context.Users.Find(3);
            accountC.Email = "user3@gmail.com";
            context.Update(accountC);
            context.SaveChanges();
        }
        private async Task UpdateAmountUserB(int ammount)
        {
            // 2. Tìm tài khoản B và cộng tiền
            var accountB = context.Users.Find(4);
            if (accountB == null)
                throw new Exception("Tài khoản B không tồn tại.");

            accountB.Amount += ammount;
            context.Update(accountB);
            context.SaveChanges();
        }
        #endregion
        
        public class UpdateUser
        {
            public string Status { get; set; }
            public DateOnly Date { get; set; }
        }
        [HttpPost("{id}/slogan")]
        public async Task<IActionResult> GetID([FromRoute] int id, [FromQuery] DateOnly date, [FromBody]UpdateUser model)
        {
            return Ok(new { FromRoute = id, FromBody = model, FromQuery = date });
        }
        [Authorize(Roles = "Adminn,Customer")]
        [HttpGet(Name = "GetWeatherForecast")]
        public async Task<IEnumerable<WeatherForecast>> Get()
        {
            // x.SaveToken = true;
            var token = await HttpContext.GetTokenAsync("access_token");
            var user = User.Identity; // Tìm claim với thông tin từ cái này
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
        public class TokenModel
        {
            public string AccessToken { get; set; }
            public string RefreshToken { get; set; }
        }
        // đọc access token thử coi hợp lệ ko = openiddict
        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<ActionResult> RefreshToken([FromBody] TokenModel model)
        {
            try
            {
                var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                                "https://localhost:7293/.well-known/openid-configuration",
                                new OpenIdConnectConfigurationRetriever());

                var config = await configManager.GetConfigurationAsync();
                var validationParams = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = config.SigningKeys,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(model.AccessToken, validationParams, out var validatedToken);
                if (!principal.Identity.IsAuthenticated) throw new Exception("Chua dang nhap");
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize(Policy = "InGenZ")]
        [HttpGet("CheckPolicy")]
        public IEnumerable<WeatherForecast> CheckPolicy()
        {
            var user = User.Identity; // Tìm claim với thông tin từ cái này
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [Authorize]
        [HttpPost]
        [RequiredScope("api.write")]
        public IActionResult GetUsers()
        {
            Console.WriteLine("test scope api write");
            return Ok(true);
        }
        // 5. Custom Attribute để kiểm tra Required Scope
        private class RequiredScopeAttribute : Attribute, IAuthorizationFilter
        {
            private readonly string _requiredScope;

            public RequiredScopeAttribute(string requiredScope)
            {
                _requiredScope = requiredScope;
            }

            public void OnAuthorization(AuthorizationFilterContext context)
            {
                var user = context.HttpContext.User;
                var scopes = user.Claims.FirstOrDefault(x=>x.Type == "scope").Value;
                                      
                if (!scopes.Contains(_requiredScope))
                {
                    context.Result = new ForbidResult();
                }
            }
        }
    }
}