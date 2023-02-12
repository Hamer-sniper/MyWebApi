using Microsoft.EntityFrameworkCore;
using MyWebApi.Models;
using MyWebApi.DataContext;
using MyWebApi.Interfaces;

namespace MyWebApi.Controllers
{
    public class DataBookData : IDataBookData
    {
        private readonly DataBookContext dBContext;

        public DataBookData(DataBookContext dB)
        {
            dBContext = dB;
        }

        /// <summary>
        /// Получить все записи из БД.
        /// </summary>
        /// <returns></returns>
        public List<DataBook> GetAllDatabooks()
        {
            return dBContext.DataBook.ToList();
        }

        /// <summary>
        /// Добавить запись в БД.
        /// </summary>
        /// <param name="dataBook">Запись</param>
        public void CreateDataBook(DataBook dataBook)
        {
            dBContext.DataBook.Add(dataBook);
            dBContext.SaveChanges();
        }

        /// <summary>
        /// Получить запись из БД.
        /// </summary>
        /// <param name="dataBookId">Id записи</param>
        /// <returns>Запись</returns>
        public DataBook ReadDataBook(int dataBookId)
        {
            return dBContext.DataBook.FirstOrDefault(d => d.Id == dataBookId);
        }

        /// <summary>
        /// Изменить запсиь в БД.
        /// </summary>
        /// <param name="dataBook">Запись</param>
        public void UpdateDataBook(DataBook dataBook)
        {
            dBContext.Entry(dataBook).State = EntityState.Modified;
            dBContext.SaveChanges();
        }

        /// <summary>
        /// Удалить запись из БД.
        /// </summary>
        /// <param name="dataBookId">Id записи</param>
        public void DeleteDataBook(DataBook dataBook)
        {
            dBContext.DataBook.Remove(dataBook);
            dBContext.SaveChanges();
        }
    }
}