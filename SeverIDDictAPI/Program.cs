
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SeverIDDictAPI.Data;
using System.Security.Cryptography;

namespace SeverIDDictAPI
{
    public class RsaKeyService1
    {
        public RsaSecurityKey SigningKey { get; }
        public RsaSecurityKey EncryptionKey { get; }

        public RsaKeyService1()
        {
            // 1️⃣ Load hoặc tạo Signing key (persisted to file)
            var signingKeyPath = Path.Combine(AppContext.BaseDirectory, "signing-key.xml");
            SigningKey = LoadOrCreateRsaKey(signingKeyPath, "signing-key-2025");

            // 2️⃣ Load hoặc tạo Encryption key (persisted to file)
            var encryptionKeyPath = Path.Combine(AppContext.BaseDirectory, "encryption-key.xml");
            EncryptionKey = LoadOrCreateRsaKey(encryptionKeyPath, "encryption-key-2025");
        }

        private static RsaSecurityKey LoadOrCreateRsaKey(string filePath, string keyId)
        {
            RSA rsa = RSA.Create(2048);

            if (File.Exists(filePath))
            {
                var xml = File.ReadAllText(filePath);
                rsa.FromXmlString(xml);
            }
            else
            {
                var xml = rsa.ToXmlString(includePrivateParameters: true);
                File.WriteAllText(filePath, xml);
            }

            var key = new RsaSecurityKey(rsa)
            {
                KeyId = keyId  // 🔥 Gán KeyId rõ ràng, cố định ,sẽ ko bị đổi khi app restart
            };

            return key;
        }
    }

    /// <summary>
    ///     Core Identity + OpenIddict
    /// </summary>
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddDbContext<ApplicationDbContext>(option =>
            {
                option.UseSqlServer(builder.Configuration.GetConnectionString("SqlConnectionStr"));
                // Add Openiddict
                option.UseOpenIddict();
            });
            builder.Services.AddOpenApi();
            builder.Services.AddControllersWithViews();

            var rsaKeyService1 = new RsaKeyService1();
            builder.Services.AddSingleton(rsaKeyService1);

            //Configure OpenIddict 
            // sau chạy dotnet ef migrations add OpenIDDict là có 4 bảng tbo
            builder.Services.AddOpenIddict()
                           .AddCore(coreOptions =>
                           {
                               coreOptions.UseEntityFrameworkCore()
                                  .UseDbContext<ApplicationDbContext>();
                           })
            .AddServer(options =>
            {
                options.SetIssuer(new Uri("https://localhost:7293/"));
                options.SetTokenEndpointUris("connect/token");
                options.SetAuthorizationEndpointUris("connect/authorize");
                options.SetIntrospectionEndpointUris("token/introspect");
                options.SetRevocationEndpointUris("token/revoke");

                options.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow();

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60))
                       .SetRefreshTokenLifetime(TimeSpan.FromDays(7));
                options
                    .AddSigningKey(rsaKeyService1.SigningKey)
                    .AddEncryptionKey(rsaKeyService1.EncryptionKey) // 👈 Giải quyết lỗi
                    .DisableAccessTokenEncryption(); // 👈 tắt mã hóa access token (nếu muốn)

                // trong thời gian này được cấp token ko giới hạn
                options.SetRefreshTokenReuseLeeway(TimeSpan.FromMilliseconds(2000));
                    //// tắt mã hóa access token nếu bạn dùng JWT
                options.UseAspNetCore()
                .EnableTokenEndpointPassthrough()
                .EnableAuthorizationEndpointPassthrough();
            });

            builder.Services.AddHostedService<Worker>();
            builder.Services
                    .AddAuthentication(
                        options =>
                        {
                            options.DefaultScheme = "MyApp.Auth";
                            options.DefaultChallengeScheme = "MyApp.Auth";
                        }
                    )
                    .AddCookie("MyApp.Auth", options =>
                    {
                        options.Cookie.HttpOnly = true;
                        options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
                        options.LoginPath = "/Home/Login";
                        options.AccessDeniedPath = "/Home/Privacy";
                        options.SlidingExpiration = true;
                    });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }
            app.UseStaticFiles();
            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            //app.MapControllers();

            app.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");


            app.Run();
        }
    }
}
