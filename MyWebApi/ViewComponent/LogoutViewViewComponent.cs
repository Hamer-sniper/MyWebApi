using Microsoft.AspNetCore.Mvc;

namespace MyWebApi.Component
{
    public class LogoutViewViewComponent : ViewComponent
    {
        public IViewComponentResult Invoke()
        {
            return View();
        }
    }

}
