using Microsoft.EntityFrameworkCore;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Persistence.Repositories;

public class GenericRepository<T>(AppDbContext db) : IGenericRepository<T> where T : class
{
    protected readonly AppDbContext Db = db;

    public async Task<T?> GetByIdAsync(Guid id) =>
        await Db.Set<T>().FindAsync(id);

    public async Task<IReadOnlyList<T>> GetAllAsync() =>
        await Db.Set<T>().ToListAsync();

    public async Task AddAsync(T entity)
    {
        await Db.Set<T>().AddAsync(entity);
        await Db.SaveChangesAsync();
    }

    public async Task DeleteAsync(Guid id)
    {
        var entity = await Db.Set<T>().FindAsync(id);
        if (entity is not null)
        {
            Db.Set<T>().Remove(entity);
            await Db.SaveChangesAsync();
        }
    }

    public async Task SaveChangesAsync() =>
        await Db.SaveChangesAsync();
}
