using Microsoft.EntityFrameworkCore;
using Protector.API.Hubs;
using Protector.Infrastructure;
using Protector.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

// Controllers (ScanController)
builder.Services.AddControllers();

// SignalR — real-time communication with React
builder.Services.AddSignalR();

// All our scan services (analyzers, crawler, use case, database)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddProtector(connectionString);

// CORS — allow any localhost port (Vite may pick a different port if 5173 is busy)
builder.Services.AddCors(options =>
{
    options.AddPolicy("ReactApp", policy =>
        policy.SetIsOriginAllowed(origin =>
                new Uri(origin).Host == "localhost")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials()); // required for SignalR
});

var app = builder.Build();

// Auto-apply migrations on startup (SQL Server only, skip InMemory)
if (!string.IsNullOrEmpty(connectionString))
{
    using var scope = app.Services.CreateScope();
    scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.Migrate();
}

app.UseCors("ReactApp");
app.UseAuthorization();
app.MapControllers();

// SignalR hub endpoint — React connects here for real-time progress
app.MapHub<ScanHub>("/hubs/scan");

app.Run();
