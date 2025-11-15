using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IO.Pipelines;
using System.Net.Http;
using System.Text.Json;
using System.Text.Unicode;

namespace ResourceAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenAPIController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        public AuthenAPIController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }
        [HttpGet("/login")]
        public async Task<IActionResult> LoginWithServer()
        {
            var scope = Uri.EscapeDataString("email offline_access profile api.write");
            var url = $"https://localhost:7293/connect/authorize?" +
                $"client_id=test_client" +
                $"&response_type=code" +
                $"&state=af0ifjsldkj" +
                $"&redirect_uri=https://localhost:7240/callbackurl" +
                $"&scope={scope}";
            return Ok(url);
        }
        [HttpGet("/logout/{refreshToken}")]
        public async Task<IActionResult> Logout(string refreshToken)
        {
            //Revoke là xong 
            var parameters = new Dictionary<string, string>
            {
                { "client_id", "test_client" },
                { "token", refreshToken }, // Replace with actual code
            };
            var httpClient = _httpClientFactory.CreateClient();
            var content = new FormUrlEncodedContent(parameters);
            //  token/revoke
            var zzz  = await httpClient.PostAsync("https://localhost:7293/token/revoke", content);
            return Ok();
        }
        [HttpGet("/callbackurl")]
        public async Task<IActionResult> CallBackUrl([FromQuery]string code)
        {
            var parameters = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "client_id", "test_client" },
                { "code", code }, // Replace with actual code
                {"redirect_uri","https://localhost:7240/callbackurl" }
            };
            var httpClient = _httpClientFactory.CreateClient();
            var content = new FormUrlEncodedContent(parameters);
            var response = await httpClient.PostAsync("https://localhost:7293/connect/token", content);
            // Read and output the response
            var responseContent = await response.Content.ReadAsStringAsync();

            var path=  Environment.CurrentDirectory+"Token.json";

            System.IO.File.WriteAllText(path,responseContent);
            return Ok();
        }
    }
}
