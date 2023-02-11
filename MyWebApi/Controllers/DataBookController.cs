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
        public IActionResult AddDataBook()
        {
            return View();
        }

        [HttpGet]
        public IActionResult EditDataBook(int dataBookId)
        {
            var MyData = new DataBookContext();

            return View(MyData.DataBook.FirstOrDefault(d => d.Id == dataBookId));
        }

        [HttpPost]
        public IActionResult GetDataFromField(DataBook dataBook)
        {
            using (var db = new DataBookContext())
            {
                db.DataBook.Add(dataBook);
                db.SaveChanges();
            }
            return Redirect("~/");
        }

        [HttpGet]
        public IActionResult DeleteDataBook(int dataBookId)
        {
            var MyData = new DataBookContext();

            return View(MyData.DataBook.FirstOrDefault(d => d.Id == dataBookId));
        }

        [HttpPost]
        public IActionResult DeleteDataFromField(DataBook dataBook)
        {
            using (var db = new DataBookContext())
            {
                var dataBookToDelete = db.DataBook.FirstOrDefault(d => d.Id == dataBook.Id);
                if (dataBookToDelete != null)
                {
                    db.DataBook.Remove(dataBookToDelete);
                    db.SaveChanges();
                }                
            }
            return Redirect("~/");
        }

        [HttpPost]
        public IActionResult EditDataFromField(DataBook dataBook)
        {
            using (var db = new DataBookContext())
            {
                db.Entry(dataBook).State = EntityState.Modified;
                db.SaveChanges();
            }
            return Redirect("~/");
        }

        [HttpGet]
        public IActionResult GetDataBook(int dataBookId)
        {
            var MyData = new DataBookContext();

            return View(MyData.DataBook.FirstOrDefault(d => d.Id == dataBookId));
        }
    }
}