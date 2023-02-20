using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyWebApi.Authentification;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MyWebApi.Controllers
{
    public class AccountController : Controller
    {

        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        // Работа с токенами
        private const string SECRET_KEY = "TQvgjeABMPOwCycOqah5EQu5yyVjpmVG";
        public static readonly SymmetricSecurityKey SIGNING_KEY = new
                      SymmetricSecurityKey(Encoding.UTF8.GetBytes(SECRET_KEY));

        [HttpGet]
        [AllowAnonymous]
        [Route("/Token/{username}/{password}")]
        public IActionResult Get(string username, string password)
        {
            if (LoginResultIsSucceed(username, password).Result)
                return new ObjectResult(GenerateToken(username));
            else
                return BadRequest("Invalid User");
        }

        private string GenerateToken(string username)
        {
            var token = new JwtSecurityToken(
                issuer: "myapi",
                audience: "myapi",
                claims: new Claim[] { new Claim(ClaimTypes.Name, username) },
                notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                expires: new DateTimeOffset(DateTime.Now.AddMinutes(60)).DateTime,
                signingCredentials: new SigningCredentials(SIGNING_KEY,
                                                    SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        public async Task<bool> LoginResultIsSucceed(string login, string password)
        {
            var loginResult = await _signInManager.PasswordSignInAsync(login,
                password,
                false,
                lockoutOnFailure: false);

            if (loginResult.Succeeded)
            {
                return true;
            }

            return false;
        }

        [HttpGet]
        public IActionResult Login(string returnUrl)
        {
            if (string.IsNullOrWhiteSpace(returnUrl)) returnUrl = "/";

            return View(new UserLogin()
            {
                ReturnUrl = returnUrl
            });
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(UserLogin model)
        {
            if (ModelState.IsValid)
            {
                if (LoginResultIsSucceed(model.LoginProp, model.Password).Result)
                {
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }

                    return RedirectToAction("Index", "DataBook");
                }

            }

            ModelState.AddModelError("", "Пользователь не найден");
            return View(model);
        }


        [HttpGet]
        public IActionResult Register()
        {
            return View(new UserRegistration());
        }

        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(UserRegistration model)
        {
            if (ModelState.IsValid)
            {
                var user = new User { UserName = model.LoginProp };
                var createResult = await _userManager.CreateAsync(user, model.Password);

                if (createResult.Succeeded)
                {
                    await _signInManager.SignInAsync(user, false);
                    return RedirectToAction("Index", "DataBook");
                }
                else
                {
                    foreach (var identityError in createResult.Errors)
                    {
                        ModelState.AddModelError("", identityError.Description);
                    }
                }
            }

            return View(model);
        }


        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "DataBook");
        }

        [HttpGet]
        public IActionResult AccessDenied(string returnUrl)
        {
            return View();
        }

        [HttpPost]
        public IActionResult AccessDenied(UserLogin model)
        {
            return RedirectToAction("Index", "DataBook");
        }
    }
}