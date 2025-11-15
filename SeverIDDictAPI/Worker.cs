using OpenIddict.Abstractions;
using System.Resources;

namespace SeverIDDictAPI
{
    public class Worker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public Worker(IServiceProvider serviceProvider)
            => _serviceProvider = serviceProvider;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var lstAppDescriptor = new[]
            {
                new OpenIddictApplicationDescriptor
                {
                    ClientId = "test_client",
                    DisplayName = "Bao_API_APP",
                    ClientType = OpenIddictConstants.ClientTypes.Public, // ko cần gửi client_secret
                    RedirectUris = { new Uri("https://localhost:7240/callbackurl") }, // URL callback của client
                    Permissions =
                    {
                            // Để xác thực đăng nhập (authorization endpoint)
                        OpenIddictConstants.Permissions.Endpoints.Authorization,
                        OpenIddictConstants.Permissions.Endpoints.Introspection,
                        OpenIddictConstants.Permissions.Endpoints.Revocation,
                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,



                            // Để lấy access token
                        OpenIddictConstants.Permissions.Endpoints.Token,

                            // Nếu dùng OpenID Connect
                        OpenIddictConstants.Permissions.ResponseTypes.Code, // nên url truy cập phải có response_type=code

                        // phải khai như vậy thì khi scope có app.zzz nó sẽ báo lỗi 
                        //   var scope = Uri.EscapeDataString("email offline_access profile api.write api.zzz");
                        //      return Redirect($"https://localhost:7293/connect/authorize?client_id=test_client&response_type=code&scope={scope}");
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles,
                        OpenIddictConstants.Permissions.Prefixes.Scope +"api.read",
                        OpenIddictConstants.Permissions.Prefixes.Scope +"api.write",
                        OpenIddictConstants.Permissions.Prefixes.Scope + "test_scope",
                    }
                },
                new OpenIddictApplicationDescriptor
                {
                    ClientId = "test_client1",
                    ClientSecret = "test_secret",
                    DisplayName = "Bao_API_APP1",
                    ClientType = OpenIddictConstants.ClientTypes.Confidential, // gửi chung với client_secret
                    Permissions =
                    {
                            OpenIddictConstants.Permissions.Endpoints.Token,
                            OpenIddictConstants.Permissions.Endpoints.Introspection,
                            OpenIddictConstants.Permissions.Endpoints.Revocation,
                            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                            OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                            OpenIddictConstants.Permissions.Prefixes.Scope + "test_scope1"
                    }
                },
                new OpenIddictApplicationDescriptor
                {
                    ClientId = "test_client2",
                    DisplayName = "Bao_API_APP2",
                    ClientType = OpenIddictConstants.ClientTypes.Public, // ko cần gửi client_secret
                    Permissions =
                    {
                            OpenIddictConstants.Permissions.GrantTypes.Password,
                            OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                             // Để xác thực đăng nhập (authorization endpoint)
                            OpenIddictConstants.Permissions.Endpoints.Authorization,

                                // Để lấy access token
                            OpenIddictConstants.Permissions.Endpoints.Token,

                              // Nếu dùng OpenID Connect
                            OpenIddictConstants.Permissions.ResponseTypes.Code,
                            OpenIddictConstants.Permissions.Scopes.Email,
                            OpenIddictConstants.Permissions.Scopes.Profile,
                            OpenIddictConstants.Permissions.Scopes.Roles,

                            OpenIddictConstants.Permissions.Prefixes.Scope + "test_scope2"
                    }
                },
            };

            await PopulateScopes(scope, cancellationToken);
            foreach (var appDescriptor in lstAppDescriptor)
            {
                var client = await appManager.FindByClientIdAsync(appDescriptor.ClientId, cancellationToken);

                if (client == null)
                {
                    await appManager.CreateAsync(appDescriptor, cancellationToken);
                }
                else
                {
                    await appManager.UpdateAsync(client, appDescriptor, cancellationToken);
                }
            }

        }
        private async ValueTask PopulateScopes(IServiceScope scope, CancellationToken cancellationToken)
        {
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            // Seed các scopes cơ bản
            var scopes = new[]
            {
                new { Name = "profile", DisplayName = "Profile", Description = "Access to user profile" ,  Resources = Array.Empty<string>()},
                new { Name = "email", DisplayName = "Email", Description = "Access to user email" ,  Resources = Array.Empty<string>() },
                new { Name = "api.read", DisplayName = "API Read", Description = "Read access to API resources",  Resources = new string[] { "API_read" ,"Resouces"} },
                new { Name = "api.write", DisplayName = "API Write", Description = "Write access to API resources 1",  Resources = new string[] { "API_write" ,"Resouces"}},
                new { Name = "user.management", DisplayName = "User Management", Description = "Manage users",  Resources = Array.Empty<string>() },
                new { Name = "offline_access", DisplayName = "offline_access", Description = "offline_access" , Resources =Array.Empty<string>() }
            };
            foreach (var scopeInfo in scopes)
            {
                var scopeInstance = await scopeManager.FindByNameAsync(scopeInfo.Name, cancellationToken);
                if (scopeInstance == null)
                {
                    var OpenIddictScopeDescriptor = new OpenIddictScopeDescriptor()
                    {
                        Name = scopeInfo.Name,
                        DisplayName = scopeInfo.DisplayName,
                        Description = scopeInfo.Description,
                    };
                    if(scopeInfo.Resources.Length > 0)
                    {
                        foreach (var item in scopeInfo.Resources)
                        {
                            OpenIddictScopeDescriptor.Resources.Add(item);
                        }
                    } 
                    await scopeManager.CreateAsync(OpenIddictScopeDescriptor);
                }
                else
                {
                    var OpenIddictScopeDescriptor = new OpenIddictScopeDescriptor()
                    {
                        Name = scopeInfo.Name,
                        DisplayName = scopeInfo.DisplayName,
                        Description = scopeInfo.Description
                    };
                    if (scopeInfo.Resources.Length > 0)
                    {
                        foreach (var item in scopeInfo.Resources)
                        {
                            OpenIddictScopeDescriptor.Resources.Add(item);
                        }
                    }
                    await scopeManager.UpdateAsync(scopeInstance, OpenIddictScopeDescriptor, cancellationToken);
                }
            }
        }
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
