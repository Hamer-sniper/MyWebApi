using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.IdentityModel.Tokens;
using MyWebApi.Authentification;
using MyWebApi.Controllers;
using MyWebApi.DataContext;
using MyWebApi.Interfaces;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddDbContext<DataBookContext>();

builder.Services.AddScoped<IDataBookData, DataBookData>();

//builder.Services.AddMvc(options => options.EnableEndpointRouting = false);

#pragma warning disable ASP5001 // Type or member is obsolete
builder.Services.AddMvc(options => 
{
    options.EnableEndpointRouting = false;
    var policy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser().RequireAuthenticatedUser().Build();
    options.Filters.Add(new AuthorizeFilter(policy));
#pragma warning disable CS0618 // Type or member is obsolete
}).SetCompatibilityVersion(version: CompatibilityVersion.Latest);
#pragma warning restore CS0618 // Type or member is obsolete
#pragma warning restore ASP5001 // Type or member is obsolete

/*var build = builder.Services.AddIdentityCore<User>();
var identityBuilder = new IdentityBuilder(build.UserType, build.Services);
identityBuilder.AddEntityFrameworkStores<DataBookContext>();
identityBuilder.AddSignInManager<SignInManager<User>>();*/

builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<DataBookContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 6;
    options.Lockout.MaxFailedAccessAttempts = 10;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    options.Lockout.AllowedForNewUsers = true;
});

/*builder.Services.ConfigureApplicationCookie(options =>
{
    // конфигурация Cookie с целью использования их для хранения авторизации
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
});*/

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {                        
                        options.ClaimsIssuer = "myapi";
                        options.Audience = "myapi";
                        options.SaveToken = true;
                        options.TokenValidationParameters = new TokenValidationParameters()
                        {
                            IssuerSigningKey = AccountController.SIGNING_KEY,
                            ValidateLifetime = true,
                            ValidIssuer = "myapi",
                            ValidateIssuer = true,
                        };
                        options.RequireHttpsMetadata = false;
                    });
                    /*.AddCookie(options =>
                    {
                        options.Cookie.HttpOnly = true;
                        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                        options.LoginPath = "/Account/Login";
                        options.LogoutPath = "/Account/Logout";
                        options.AccessDeniedPath = "/Account/AccessDenied";
                        options.SlidingExpiration = true;
                    });*/

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var userManager = services.GetRequiredService<UserManager<User>>();
        var rolesManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        await MyWebApi.Roles.RoleInitializer.InitializeAsync(userManager, rolesManager);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}

//app.UseHttpsRedirection();

//app.UseStaticFiles();

//app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

/*app.MapControllerRoute(
    name: "default",
    pattern: "{controller=DataBook}/{action=Index}/{id?}");*/

app.UseMvc();

app.Run();
