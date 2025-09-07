using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
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
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };
        public WeatherForecastController()
        {
            
        }
        public class UpdateUser
        {
            public string Status { get; set; }
        }
        [HttpPost("{id}/slogan")]
        public async Task<IActionResult> GetID([FromRoute] int id, [FromBody]UpdateUser model)
        {
            return Ok(new { Id = id, Data = model });
        }

        [Authorize(Roles = "Admin,Customer")]
        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
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
                var zzz = await GetPrincipalFromExpiredToken(model.AccessToken);
                if (!zzz.Identity.IsAuthenticated) throw new Exception("Chua dang nhap");
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
        #region Verify Token
        public async Task<ClaimsPrincipal> GetPrincipalFromExpiredToken(string accessToken)
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
                var principal = tokenHandler.ValidateToken(accessToken, validationParams, out var validatedToken);
                return principal;
            }
            catch (Exception ex)
            {
                throw new(ex.Message + "hjihiuiii");
            }
        }
        #endregion

        [Authorize]
        [HttpPost]
        [RequiredScope("api.write")]
        public IActionResult GetUsers()
        {
            Console.WriteLine("test scope api write");
            return Ok(true);
        }
        // 5. Custom Attribute để kiểm tra Required Scope
        public class RequiredScopeAttribute : Attribute, IAuthorizationFilter
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