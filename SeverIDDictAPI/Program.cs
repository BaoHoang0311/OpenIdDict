
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
            // tải nuget .net core identity bình thường
            // xong chạy lênh dotnet ef migrations add Init
            // dotnet ef database update là xong có db của Identity
            builder.Services.AddOpenApi();

            builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
            {
                // Thiết lập về Password
                options.Password.RequireDigit = false; // Không bắt phải có số
                options.Password.RequireLowercase = false; // Không bắt phải có chữ thường
                options.Password.RequireNonAlphanumeric = false; // Không bắt ký tự đặc biệt
                options.Password.RequireUppercase = false; // Không bắt buộc chữ in
                options.Password.RequiredLength = 0; // Số ký tự tối thiểu của password
                options.Password.RequiredUniqueChars = 0; // Số ký tự riêng biệt
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@ -_.";
                // // Cấu hình Lockout - khóa user
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1); // Khóa 1 phút
                options.Lockout.MaxFailedAccessAttempts = 2; // Thất bại 2 lầ thì khóa
                //options.Lockout.AllowedForNewUsers = true;

                // // Cấu hình về User.
                options.User.RequireUniqueEmail = true; // Email là duy nhất , UserName là duy nhất thì setting strong dbContext
                                                        // // Cấu hình đăng nhập.
                options.SignIn.RequireConfirmedEmail = true;            // Cấu hình xác thực địa chỉ email (email phải tồn tại)
                // options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
                // options.SignIn.RequireConfirmedPhoneNumber = false;     // Xác thực số điện thoại
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

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

            // Dùng Microsoft.AspNetCore.Identity.EntityFrameworkCore nên ko custom được cookie ".Application" ... phải dùng default
            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Home/Login"; // Chuyển hướng đến /Home/Login khi chưa đăng nhập
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
