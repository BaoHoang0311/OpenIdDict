
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SeverIDDictAPI.Data;
using System;

namespace SeverIDDictAPI
{
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
            builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                 .AddEntityFrameworkStores<ApplicationDbContext>()
                 .AddDefaultTokenProviders();
            // Cionfigure OpenIddict
            builder.Services.AddOpenIddict()
                           .AddCore(coreOptions =>
                           {
                               coreOptions.UseEntityFrameworkCore()
                                  .UseDbContext<ApplicationDbContext>();
                           })
                           .AddServer(options =>
                           {
                               options.AllowClientCredentialsFlow().AllowRefreshTokenFlow();
                               options.AllowPasswordFlow().AllowRefreshTokenFlow();

                               // Encryption and signing of tokens
                               options
                            .AddDevelopmentEncryptionCertificate()
                            .AddDevelopmentSigningCertificate()
                            .DisableAccessTokenEncryption();

                               // Register the ASP.NET Core host and configure the ASP.NET Core options.
                               options.UseAspNetCore()
                               .EnableTokenEndpointPassthrough()
                               .EnableAuthorizationEndpointPassthrough();

                           });
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
