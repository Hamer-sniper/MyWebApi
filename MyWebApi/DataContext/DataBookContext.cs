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
                //DataSource = @"(localdb)\MSSQLLocalDB",
                DataSource = @"ST-WS-007\WEBAPITESTDB",
                InitialCatalog = @"MSSQLForAPI",
                IntegratedSecurity = true,
                UserID = "sa",
                Password = "123",
                Pooling = false,
                TrustServerCertificate = true,
                Encrypt = false
            };
            return sqlCon.ConnectionString;
        }
    }
}
