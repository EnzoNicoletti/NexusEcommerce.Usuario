using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NexusEcommerce.Usuario.Domain.Entities;

namespace NexusEcommerce.Usuario.Infrastructure.Data;

// Herda do IdentityDbContext para trazer todas as tabelas de segurança (AspNetUsers, etc)
public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    // O Entity Framework exige esse construtor para receber as opções do Program.cs
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // Nossas tabelas de negócio
    public DbSet<Cliente> Clientes { get; set; }

    // Configurações avançadas (Fluent API)
    protected override void OnModelCreating(ModelBuilder builder)
    {
        // Regra de ouro: SEMPRE chame o base.OnModelCreating primeiro ao usar Identity
        base.OnModelCreating(builder);

        // Varre a camada de Infrastructure e aplica tudo que herda de IEntityTypeConfiguration
        // (Isso faz o nosso ClienteConfiguration ser lido automaticamente!)
        builder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
    }
}