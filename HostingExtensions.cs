using AuthApi.Models;
using Duende.IdentityServer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using System.Reflection;

namespace AuthApi;
internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddControllers();
        var migrationsAssembly = typeof(Program).GetTypeInfo().Assembly.GetName().Name;
        var cn = builder.Configuration.GetConnectionString("Local");
        builder.Services.AddAutoMapper(typeof(Program));
        builder.Services.AddDbContext<ApplicationDbContext>(options =>options.UseSqlServer(cn));
        builder.Services.AddIdentity<ApplicationUser, RoleModel>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredUniqueChars = 0;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireDigit = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireUppercase = false;
        })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        builder.Services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
                options.EmitStaticAudienceClaim = true;
               
            })
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryClients(builder.Configuration.GetSection("IdentityServer:Clients"))
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddAspNetIdentity<ApplicationUser>()
            .AddResourceOwnerValidator<Config.ExtensionGrantValidator>()
            .AddProfileService<Config.CustomProfile>();
        builder.Services.AddLocalApiAuthentication();
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("IdentityScope", policy =>
            {
                policy.RequireClaim("scope", "CommerceApi");
                policy.RequireClaim("scope", "IdentityServerApi");               
                policy.RequireClaim("scope", "Authenticated");               
            });
            options.AddPolicy("IdentityScopeAdmin", policy =>
            {
                policy.RequireClaim("scope", "CommerceApi");
                policy.RequireClaim("scope", "IdentityServerApi");               
                policy.RequireClaim("scope", "Authenticated");   
                policy.RequireClaim("scope", "Admin");   
                
            });
        });
        return builder.Build();
    }
    public static WebApplication ConfigurePipeline(this WebApplication app)
    { 
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        app.UseRouting();    
        app.UseIdentityServer();
        app.UseAuthorization();
        app.MapControllers();
        return app;
    }
}
