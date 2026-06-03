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

// Security headers — fixes findings from V-Scan self-scan
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    headers["X-XSS-Protection"] = "1; mode=block";
    headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
        "connect-src 'self' ws://localhost:* wss://localhost:*";
    // HSTS only in production — localhost doesn't support HTTPS by default
    if (!context.Request.Host.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    await next();
});

app.MapControllers();

// SignalR hub endpoint — React connects here for real-time progress
app.MapHub<ScanHub>("/hubs/scan");

app.Run();

// Needed for WebApplicationFactory in E2E tests
public partial class Program { }
