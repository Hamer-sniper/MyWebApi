using MyWebApi.Models;

namespace MyWebApi.Interfaces
{
    public interface IDataBookData
    {
        /// <summary>
        /// Получить все записи из БД.
        /// </summary>
        /// <returns></returns>
        List<DataBook> GetAllDatabooks();
        /// <summary>
        /// Добавить запись в БД.
        /// </summary>
        /// <param name="dataBook">Запись</param>
        void CreateDataBook(DataBook dataBook);

        /// <summary>
        /// Получить запись из БД.
        /// </summary>
        /// <param name="dataBookId">Id записи</param>
        /// <returns>Запись</returns>
        DataBook ReadDataBook(int dataBookId);

        /// <summary>
        /// Изменить запсиь в БД.
        /// </summary>
        /// <param name="dataBook">Запись</param>
        void UpdateDataBook(DataBook dataBook);

        /// <summary>
        /// Удалить запись из БД.
        /// </summary>
        /// <param name="dataBookId">Id записи</param>
        void DeleteDataBook(DataBook dataBook);


    }
}