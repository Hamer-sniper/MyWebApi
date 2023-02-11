using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MyWebApi.Authentification;
using MyWebApi.Models;

namespace MyWebApi.DataContext
{
    public class DataBookContext : IdentityDbContext<User>
    {
        public DbSet<DataBook> DataBook { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer(GetConnectionString());
        }

        private static string GetConnectionString()
        {
            Microsoft.Data.SqlClient.SqlConnectionStringBuilder sqlCon = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder()
            {
                DataSource = @"(localdb)\MSSQLLocalDB",
                InitialCatalog = @"MSSQLLocalDemo",
                IntegratedSecurity = true,
                UserID = "sa",
                Password = "123",
                Pooling = false
            };
            return sqlCon.ConnectionString;
        }
    }
}
