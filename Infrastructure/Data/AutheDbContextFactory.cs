using System;
using Authenitcation.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Infrastructure.Data;

public class AutheDbContextFactory : IDesignTimeDbContextFactory<AutheDbContext>
{
    public AutheDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<AutheDbContext>();
        optionsBuilder.UseSqlServer("Server=SAHAND\\MSSQLSERVER2022;Database=SecuritySystem;User ID = Developer;Password = 1qaz!QAZ;TrustServerCertificate=True;");

        return new AutheDbContext(optionsBuilder.Options);
    }
}
