using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
namespace SeverIDDictAPI.Controllers
{
    [ApiController]
    public class AuthorizeController : ControllerBase
    {
        private static ClaimsIdentity Identity = new ClaimsIdentity();
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IOpenIddictTokenManager _tokenManager;
        public AuthorizeController(IOpenIddictScopeManager scopeManager, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IOpenIddictTokenManager tokenManager)
        {
            _scopeManager = scopeManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _tokenManager = tokenManager;
        }

        [HttpPost]
        [Route("connect/token")]
        public async Task<IActionResult> ConnectToken()
        {
            try
            {
                var openIdConnectRequest = HttpContext.GetOpenIddictServerRequest() ??
                         throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                Identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                IdentityUser? user = null;

                if (openIdConnectRequest.IsClientCredentialsGrantType())
                {
                    var clientId = openIdConnectRequest.ClientId;
                    var identity = new ClaimsIdentity(authenticationType: TokenValidationParameters.DefaultAuthenticationType);

                    Identity.AddClaim(Claims.ClientId, clientId);
                    identity.SetScopes(openIdConnectRequest.GetScopes());
                    var principal = new ClaimsPrincipal(identity);
                    if (!string.IsNullOrEmpty(openIdConnectRequest.Scope) && openIdConnectRequest.Scope.Split(' ').Contains(OpenIddictConstants.Scopes.OfflineAccess))
                        Identity.SetScopes(OpenIddictConstants.Scopes.OfflineAccess);
                    Identity.AddClaim(new Claim(Claims.Subject, "Sub_Client_Crendential"));
                    var signInResult = SignIn(new ClaimsPrincipal(Identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    return signInResult; // trả access token + refresh token
                }
                else if (openIdConnectRequest.IsPasswordGrantType())
                {

                    user = await _userManager.FindByNameAsync(openIdConnectRequest.Username);

                    if (user == null)
                    {
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = Errors.InvalidGrant,
                            ErrorDescription = "User does not exist"
                        });
                    }

                    // Validate the username/password parameters and ensure the account is not locked out.  lockoutOnFailure: false (Count Failed)
                    var result = await _signInManager.PasswordSignInAsync(user.UserName, openIdConnectRequest.Password, false, lockoutOnFailure: false);
                    if (!result.Succeeded)
                    {
                        if (result.IsNotAllowed)
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "User not allowed to login. Please confirm your email"
                            });
                        }

                        if (result.RequiresTwoFactor)
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "User requires 2F authentication"
                            });
                        }

                        if (result.IsLockedOut)
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "User is locked out"
                            });
                        }
                        else
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "Username or password is incorrect"
                            });
                        }
                    }

                    // The user is now validated, so reset lockout counts, if necessary
                    if (_userManager.SupportsUserLockout)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                    }

                    var password = openIdConnectRequest.Password;
                    var ddd = openIdConnectRequest.GetScopes(); // scope : offline_access
                    //// Getting scopes from user parameters (TokenViewModel) and adding in Identity 
                    Identity.SetScopes(openIdConnectRequest.GetScopes());

                    //// You have to grant the 'offline_access' scope to allow
                    //// OpenIddict to return a refresh token to the caller.
                    if (!string.IsNullOrEmpty(openIdConnectRequest.Scope) && openIdConnectRequest.Scope.Split(' ').Contains(OpenIddictConstants.Scopes.OfflineAccess))
                        Identity.SetScopes(OpenIddictConstants.Scopes.OfflineAccess);
                    Identity.SetResources(new[] { "Resource", "Another_api" }); // claim aud

                    Identity.AddClaim(new Claim(Claims.Subject, user.Id));
                    Identity.AddClaim(new Claim("userid", user.Id));
                    Identity.AddClaim(new Claim(Claims.Role, "Admin"));

                    Identity.SetDestinations(GetDestinations);

                    var signInResult = SignIn(new ClaimsPrincipal(Identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    return signInResult; // trả access token + refresh token
                }
                else if (openIdConnectRequest.IsRefreshTokenGrantType())
                {
                    // chỉ dùng refreshtoken 1 lần (sau khi dùng status "reddemed"
                    // mà dùng lại lần nữa để lấy accesstoken thì hệ thống openiddict revoked toàn bộ những gì trong 
                    // "AuthorizationID" (tbo.Openiddictoken)
                    var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    var oi_au_id = result.Principal?.Claims.FirstOrDefault(c => c.Type == "oi_au_id")?.Value;

                    if (string.IsNullOrEmpty(oi_au_id))
                        return BadRequest("oi_au_id");

                    await _tokenManager.RevokeByAuthorizationIdAsync(oi_au_id);
                    // gt:refresh_token
                    var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
                    return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
                else if (openIdConnectRequest.IsAuthorizationCodeGrantType())
                {
                    var authenticateResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    var principal = authenticateResult.Principal;
                    var scopes = principal.GetScopes(); // lấy trong request

                    var listScopeDb = new List<OpenIddictScopeDescriptor>();

                    // check scope 
                    // lấy những scope Có Resourse = "API_hihi" .Resourses = Hashset<string>

                    var scopeNames = new List<string>();

                    await foreach (var scope in _scopeManager.ListAsync())
                    {
                        var resources = await _scopeManager.GetResourcesAsync(scope);

                        if (resources.Contains("API_read"))
                        {
                            var name = await _scopeManager.GetNameAsync(scope);
                            scopeNames.Add(name);
                        }
                    }

                    if (!authenticateResult.Succeeded)
                    {
                        return Forbid();
                    }
                    // oi_scp="email" oi_scp="offline_access"
                    var ScopeEmail = authenticateResult.Principal.Claims.FirstOrDefault(x => x.Type == OpenIddictConstants.Claims.Private.Scope && x.Value == OpenIddictConstants.Scopes.Email);
                    if (ScopeEmail != null)
                    {
                        var emaill = authenticateResult.Principal.Claims.FirstOrDefault(x => x.Type == Claims.Email).Value;
                        Identity.AddClaim(new Claim(Claims.Email, emaill));
                    }
                    Identity.AddClaim(new Claim(Claims.Subject, authenticateResult.Principal.Claims.FirstOrDefault(x => x.Type == "userid").Value));
                    Identity.AddClaim(new Claim("userid", authenticateResult.Principal.Claims.FirstOrDefault(x => x.Type == "userid").Value));
                    Identity.AddClaim(new Claim(Claims.Role, "Admin"));
                    Identity.AddClaim(new Claim(Claims.Birthdate, "1995"));

                    // Thêm audience claims (trong jwt token) dựa trên scopes
                    if (scopes.Contains("api.read") || scopes.Contains("api.write"))
                    {
                        Identity.SetResources(new[] { "Resource", "Api-Resource" });
                    }

                    // ko có cái này thì payload chỉ có mỗi thằng sub , còn mấy cái claim custom hầu như ko có
                    Identity.SetDestinations(GetDestinations);

                    #region Payload sau khi SetDestinations
                    //{
                    //  "iss": "https://localhost:7293/",
                    //  "exp": 1748880522,
                    //  "iat": 1748878722,
                    //  "aud": [
                    //    "Resource",
                    //    "Api-Resource"
                    //  ],
                    //  "scope": "email offline_access",
                    //  "jti": "e4d20641-529d-4755-bdec-b7b038fc59b6",
                    //  "email": "user@example.com",
                    //  "sub": "1bcc8a26-4a04-44e0-846f-6292f74fcbdf",
                    //  "userid": "1bcc8a26-4a04-44e0-846f-6292f74fcbdf",
                    //  "role": "Admin",
                    //  "oi_prst": "test_client",
                    //  "oi_au_id": "f3333ab0-1194-475c-a1f6-ad752400b394",
                    //  "client_id": "test_client",
                    //  "oi_tkn_id": "e2709886-ee95-4f20-8b93-92ca416e055b"
                    //}
                    #endregion

                    var newPrincipal = new ClaimsPrincipal(Identity);
                    newPrincipal.SetScopes(scopes);
                    var signInResult = SignIn(newPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    return signInResult; // trả access token + refresh token

                }
                else
                {
                    return BadRequest(new
                    {
                        error = Errors.UnsupportedGrantType,
                        error_description = "The specified grant type is not supported."
                    });
                }

            }
            catch (Exception ex)
            {
                return BadRequest(new OpenIddictResponse()
                {
                    Error = Errors.ServerError,
                    ErrorDescription = "Invalid login attempt"
                });
            }
        }
        
        /*
         * 1 MVC Controller ( LoginWithServer) trong đó có query param 
         * 2 vào thằng (connect/authorize)  
         * 3 lấy được thông tin các param từ trang MVC (ResourceMVC) chuyển qua
         * 3.1 nếu chưa đăng nhập thì 
         *              1) redirect Home/Login của serverOpenID đăng nhập -> đăng nhập Home/Login (serverOpenID) 
         *              2) đăng nhập xong redirect ("connect/authorize")
         *              3) lúc này đã đăng nhập rồi xong set scope của thằng openiddict
         *              4)  return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
         *              5) Redirect vào returnURL đã setting trong Worker.cs (RedirectUris = { new Uri("https://localhost:7224/Home/Privacy") }, //(ResourceMVC)
         *             -> MVC truy cập (conntect/token) lấy access/refresh token
         * 3.2 nếu đăng nhập rồi thì lấy thông tin param đem vào "OpenIddict.Server.AspNetCore"
         *              ->Redirect vào returnURL đã setting trong Worker.cs (RedirectUris = { new Uri("https://localhost:7224/Home/Privacy") }, //(ResourceMVC)
         */
        [HttpGet("connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            if (request == null)
                throw new InvalidOperationException("Invalid OpenIddict request.");

            if (!User.Identity.IsAuthenticated) // chưa đăng nhập
            {
                return Challenge(new AuthenticationProperties
                {
                    RedirectUri = Request.Path + Request.QueryString // truy cập vào trang Home/Login+RedirectUri=... ( RedirectUri = string ReturnUrl)
                });
            }
            // Lấy thông tin user đăng nhập
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Forbid();
            var requestedScopes = request.Scope?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
            // Validate scopes
            var validScopes = new List<string>();
            foreach (var scope in requestedScopes)
            {
                var scopeEntity = await _scopeManager.FindByNameAsync(scope);
                if (scopeEntity != null)
                {
                    validScopes.Add(scope);
                }
            }
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Email);
            if (validScopes.Contains("profile"))
            {
                identity.AddClaim("name", "John Doe");
                identity.AddClaim("given_name", "John");
                identity.AddClaim("family_name", "Doe");
            }
            if (validScopes.Contains("email"))
            {
                identity.AddClaim(Claims.Email, user.Email);
                identity.AddClaim("userid", user.Id);
            }
            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(validScopes);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        #region Private Methods

        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            return claim.Type switch
            {
                Claims.Role or "userid" or Claims.Email or Claims.Audience or Claims.Birthdate => new[] { Destinations.AccessToken }, // Chỉ thêm sub vào identity token
                _ => Array.Empty<string>(),                           // Các claim khác không thêm vào token
            };
        }

        #endregion
        [Route("token/logout")]
        [HttpPost]
        public async Task<IActionResult> Logout([FromForm] string accessToken)
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

            SecurityToken validatedToken;

            // thu hồi toàn bộ accesstoken + refre  shtoken của authorizeID đó
            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(accessToken, validationParams, out validatedToken);
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);


            // Đăng xuất khỏi cookie/identity (nếu có)
            var oi_au_id = principal.Claims.FirstOrDefault(c => c.Type == "oi_au_id")?.Value;
            if (string.IsNullOrEmpty(oi_au_id))
                return BadRequest("oi_au_id");
            await _tokenManager.RevokeByAuthorizationIdAsync(oi_au_id);
            return Ok();
        }
    }
}
