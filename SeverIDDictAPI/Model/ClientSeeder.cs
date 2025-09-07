using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace OpenIdDictSample
{
    public class ClientSeeder : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public ClientSeeder(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }


        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            //await PopulateScopes(scope, cancellationToken);

            await PopulateInternalApps(scope, cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        private async ValueTask PopulateScopes(IServiceScope scope, CancellationToken cancellationToken)
        {
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            var scopeDescriptor = new OpenIddictScopeDescriptor
            {
                Name = "test_scope",
                Resources = { "test_resource", "test_abc" }
            };

            var scopeInstance = await scopeManager.FindByNameAsync(scopeDescriptor.Name, cancellationToken);

            if (scopeInstance == null)
            {
                await scopeManager.CreateAsync(scopeDescriptor, cancellationToken);
            }
            else
            {
                await scopeManager.UpdateAsync(scopeInstance, scopeDescriptor, cancellationToken);
            }
        }

        private async ValueTask PopulateInternalApps(IServiceScope scopeService, CancellationToken cancellationToken)
        {
            var appManager = scopeService.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var lstAppDescriptor = new[]
            {
                new OpenIddictApplicationDescriptor
                {
                    ClientId = "test_client",
                    DisplayName = "Bao_API_APP",
                    ClientType = OpenIddictConstants.ClientTypes.Public, // ko cần gửi client_secret
                    RedirectUris = { new Uri("https://localhost:7224/Home/Privacy") }, // URL callback của client
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
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

                        OpenIddictConstants.Permissions.Prefixes.Scope + "test_scope"
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
    }
}