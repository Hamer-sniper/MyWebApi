using Microsoft.AspNetCore.Identity;
using MyWebApi.Authentification;
using MyWebApi.Controllers;
using MyWebApi.DataContext;
using MyWebApi.Interfaces;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddDbContext<DataBookContext>();

builder.Services.AddScoped<IDataBookData, DataBookData>();

builder.Services.AddMvc();

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

builder.Services.ConfigureApplicationCookie(options =>
{
    // конфигурация Cookie с целью использования их для хранения авторизации
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
});

var app = builder.Build();

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=DataBook}/{action=Index}/{id?}");

app.Run();
