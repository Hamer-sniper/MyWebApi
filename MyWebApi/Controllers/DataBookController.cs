using Microsoft.AspNetCore.Mvc;
using MyWebApi.Models;
using Microsoft.EntityFrameworkCore;
using MyWebApi.DataContext;
using MyWebApi.Interfaces;

namespace MyWebApi.Controllers
{
    public class DataBookController : Controller
    {
        private readonly IDataBookData dataBookData;
        public DataBookController(IDataBookData dBData)
        {
            dataBookData = dBData;
        }

        [HttpGet]
        public IActionResult Index()
        {
            ViewBag.DataBook = dataBookData.GetAllDatabooks();
            return View();
        }

        [HttpGet]
        public IActionResult GetDataBook(int dataBookId)
        {
            return View(dataBookData.ReadDataBook(dataBookId));
        }

        [HttpGet]
        public IActionResult AddDataBook()
        {
            return View();
        }

        [HttpPost]
        public IActionResult AddDataFromField(DataBook dataBook)
        {
            dataBookData.CreateDataBook(dataBook);
            return Redirect("~/");
        }

        [HttpPost]
        public IActionResult EditDataBook(int dataBookId)
        {
            return View(dataBookData.ReadDataBook(dataBookId));
        }

        [HttpPost]
        public IActionResult EditDataFromField(DataBook dataBook)
        {
            dataBookData.UpdateDataBook(dataBook);
            return Redirect("~/");
        }

        [HttpPost]
        public IActionResult DeleteDataBook(int dataBookId)
        {
            return View(dataBookData.ReadDataBook(dataBookId));
        }

        [HttpPost]
        public IActionResult DeleteDataFromField(DataBook dataBook)
        {
            dataBookData.DeleteDataBook(dataBook);
            return Redirect("~/");
        }
    }
}