
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
namespace ResourceAPI
{
    public class TokenIntrospectionService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _config;

        public TokenIntrospectionService(HttpClient httpClient, IConfiguration config)
        {
            _httpClient = httpClient;
            _config = config;
        }

        public async Task<bool> IsTokenActiveAsync(string token)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7293/token/introspect");
            // Form data
            request.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", "test_client"),
                new KeyValuePair<string, string>("token", token),
            });

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
                return false;

            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<JsonElement>(json);

            return result.TryGetProperty("active", out var active) && active.GetBoolean();
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddHttpClient();
            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();
            builder.Services.AddMemoryCache();
            builder.Services.AddSwaggerGen(options =>
            {
                #region jwt authentication
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description =
                        "JWT Authorization header using the Bearer scheme. \r\n\r\n " +
                        "Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\n" +
                        "Example: \"12345abcdef\"",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Scheme = "Bearer"
                });
                options.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header
                        },
                        new List<string>()
                    }
                });
                #endregion
            });
            builder.Services.AddHttpClient<TokenIntrospectionService>();

            builder.Services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                var SettingJs = builder.Configuration.GetSection("AuthServer");
                options.Authority = "https://localhost:7293/"; // nó tự lấy key /.wellknow/jwks ko cần custom như bên dưới                          
                options.Audience = "Resource";
                // name of the API resource
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateLifetime = true,  // Phải bật lên
                    ClockSkew = TimeSpan.Zero // Loại bỏ khoảng trễ mặc định
                };
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var tokenService = context.HttpContext.RequestServices
                                        .GetRequiredService<TokenIntrospectionService>();

                        var tokenString = "";
                        // Hoặc lấy từ Authorization header
                        var authHeader = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault();
                        if (authHeader != null && authHeader.StartsWith("Bearer "))
                        {
                            tokenString = authHeader.Substring("Bearer ".Length).Trim();
                        }
                        var isActive = await tokenService.IsTokenActiveAsync(tokenString);

                        if (!isActive)
                        {
                            context.Fail("Token has been revoked");
                        }


                        var roleClaim = context.Principal.FindFirst(ClaimTypes.Role);
                        if (roleClaim == null)
                        {
                            // Không có claim "role", từ chối xác thực
                            context.Fail("Missing required 'role' claim.");
                        }

                        //return Task.CompletedTask;
                    }
                };
            });

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("InGenZ", policy =>
                {
                    policy.Requirements.Add(new GenZrequirement(1997, 2012));
                });
            });


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }
            app.UseSwagger();
            app.UseSwaggerUI();
            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
