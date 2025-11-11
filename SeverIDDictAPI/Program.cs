
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
                options.SetAuthorizationEndpointUris("/connect/authorize");
                options.SetIntrospectionEndpointUris("token/introspect");

                options.AllowClientCredentialsFlow().AllowRefreshTokenFlow();
                options.AllowPasswordFlow().AllowRefreshTokenFlow();
                options.AllowAuthorizationCodeFlow();

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60));

                // Encryption and signing of tokens
                options
                    .AddSigningKey(rsaKeyService1.SigningKey)
                    .AddEncryptionKey(rsaKeyService1.EncryptionKey) // 👈 Giải quyết lỗi
                    .DisableAccessTokenEncryption(); // 👈 tắt mã hóa access token (nếu muốn)
                                                     // ✅ Add real certificates


                // tắt mã hóa access token nếu bạn dùng JWT
                options.UseAspNetCore()
                .EnableTokenEndpointPassthrough()
                .EnableAuthorizationEndpointPassthrough();
            });

            builder.Services.AddHostedService<Worker>();

            builder.Services.ConfigureApplicationCookie(options =>
            {
                // Thay đổi tên cookie (mặc định: ".AspNetCore.Identity.Application")
                options.Cookie.Name = ".MyApp.Auth";

                // Những tuỳ chỉnh bạn đã có
                options.LoginPath = "/Home/Login";
                options.AccessDeniedPath = "/Home/Privacy";

                // Một vài tuỳ chọn hay dùng
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // production: Always
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
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
