using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using NexusEcommerce.Usuario.Domain.Entities;
using NexusEcommerce.Usuario.Domain.ValueObjects;

namespace NexusEcommerce.Usuario.Infrastructure.Data.Configurations;

public class ClienteConfiguration : IEntityTypeConfiguration<Cliente>
{
    public void Configure(EntityTypeBuilder<Cliente> builder)
    {
        builder.ToTable("Clientes");
        builder.HasKey(c => c.Id);

        builder.Property(c => c.IdentityId).IsRequired().HasColumnType("varchar(450)");
        builder.Property(c => c.NomeCompleto).IsRequired().HasColumnType("varchar(150)");
        builder.Property(c => c.Email).IsRequired().HasColumnType("varchar(100)");

        // Conversão de Value Object para String (Banco) e vice-versa (Aplicação)
        builder.Property(c => c.Cpf)
            .HasConversion(
                cpf => cpf.Numero,
                numero => new Cpf(numero)
            )
            .IsRequired()
            .HasColumnType("varchar(11)")
            .HasColumnName("Cpf");

        builder.Property(c => c.Cep).HasColumnType("varchar(9)");
        builder.Property(c => c.Estado).HasColumnType("varchar(2)");

        // Índices de performance e unicidade
        builder.HasIndex(c => c.Cpf).IsUnique().HasDatabaseName("IX_Clientes_Cpf_Unico");
        builder.HasIndex(c => c.IdentityId).IsUnique().HasDatabaseName("IX_Clientes_IdentityId_Unico");
    }
}