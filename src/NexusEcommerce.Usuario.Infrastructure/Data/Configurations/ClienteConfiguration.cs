using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using NexusEcommerce.Usuario.Domain.Entities;
using NexusEcommerce.Usuario.Domain.Enums;
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

        // Configuração do Role (enum UserRole: Cliente=0, Moderador=1, Administrador=2)
        // IsRequired(): obrigatório (todo cliente tem um role)
        // HasDefaultValue(UserRole.Cliente): novo cliente começa com role "Cliente"
        // HasConversion<int>(): armazena enum como int no banco (0, 1, 2)
        // Vantagem: melhor performance (comparação numérica é mais rápida que string)
        // Exemplo no banco: [Role] INT NOT NULL DEFAULT 0
        builder.Property(c => c.Role)
            .IsRequired()
            .HasDefaultValue(UserRole.Cliente)
            .HasConversion<int>();

        // Índices de performance e unicidade
        builder.HasIndex(c => c.Cpf).IsUnique().HasDatabaseName("IX_Clientes_Cpf_Unico");
        builder.HasIndex(c => c.IdentityId).IsUnique().HasDatabaseName("IX_Clientes_IdentityId_Unico");
    }
}