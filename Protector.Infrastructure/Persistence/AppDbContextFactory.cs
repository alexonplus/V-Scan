using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Protector.Infrastructure.Persistence;

// Used only by dotnet-ef at design time (migrations) — not used at runtime
public sealed class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=VScan;Trusted_Connection=True;")
            .Options;

        return new AppDbContext(options);
    }
}
