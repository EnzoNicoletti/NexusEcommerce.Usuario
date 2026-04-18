using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using NexusEcommerce.Usuario.Domain.Entities;
//using NexusEcommerce.Usuario.Infrastructure.Entities;

namespace NexusEcommerce.Usuario.Infrastructure.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        // ════════════════════════════════════════════════════════════════════════════
        // 1. NOME DA TABELA
        // ════════════════════════════════════════════════════════════════════════════

        // Define o nome da tabela no banco de dados
        // Por padrão, EF Core usaria "RefreshTokens" (pluralizado)
        // Explícito: deixa claro a intenção
        builder.ToTable("RefreshTokens");

        // ════════════════════════════════════════════════════════════════════════════
        // 2. CHAVE PRIMÁRIA
        // ════════════════════════════════════════════════════════════════════════════

        // Configura Id como chave primária (PK)
        // Id é Guid (UNIQUEIDENTIFIER no SQL Server)
        // Será preenchido automaticamente pelo banco via DEFAULT
        builder.HasKey(rt => rt.Id);

        // Configura propriedade Id especificamente
        // HasDefaultValueSql: O banco gera um novo GUID ao inserir
        // Se não especificar DefaultValueSql, EF Core teria que gerar no C#
        // Deixar o banco gerar é mais seguro (evita colisão)
        builder.Property(rt => rt.Id)
            .HasDefaultValueSql("NEWID()");  // SQL Server: gera novo GUID

        // ════════════════════════════════════════════════════════════════════════════
        // 3. FOREIGN KEY - RELACIONAMENTO COM IDENTITY USER
        // ════════════════════════════════════════════════════════════════════════════

        // Configura IdentityUserId como propriedade
        // string: FK que referencia AspNetUsers.Id
        // IsRequired(): obrigatório (NOT NULL no SQL)
        // HasMaxLength(450): IdentityUser.Id é sempre NVARCHAR(128)
        builder.Property(rt => rt.IdentityUserId)
            .IsRequired()
            .HasMaxLength(450);

        // Configura relacionamento 1:N
        // Um IdentityUser pode ter muitos RefreshTokens
        // Múltiplos dispositivos, múltiplas sessões
        // 
        // HasOne<IdentityUser>(): um RefreshToken pertence a UM IdentityUser
        // WithMany(): um IdentityUser pode ter MUITOS RefreshTokens
        // HasForeignKey: qual propriedade é a FK (IdentityUserId)
        // OnDelete(DeleteBehavior.Cascade): se usuário é deletado, tokens também
        builder.HasOne<IdentityUser>()
            .WithMany()
            .HasForeignKey(rt => rt.IdentityUserId)
            .OnDelete(DeleteBehavior.Cascade);

        // ════════════════════════════════════════════════════════════════════════════
        // 4. TOKEN (Propriedade Crítica)
        // ════════════════════════════════════════════════════════════════════════════

        // Configura a propriedade Token
        // Token é a string aleatória (32 bytes em Base64 = ~43-44 caracteres)
        // IsRequired(): obrigatório (NOT NULL)
        // HasMaxLength(500): margem de segurança (real são ~44 caracteres)
        builder.Property(rt => rt.Token)
            .IsRequired()
            .HasMaxLength(500);

        // Índice UNIQUE em Token
        // Motivo: buscar/validar token deve ser rápido
        // UNIQUE: garante que não há dois tokens iguais (teoricamente impossível, mas seguro)
        // Performance: SELECT WHERE Token = @token é muito mais rápido com índice
        // Sem índice: full table scan (lento com muitos registros)
        builder.HasIndex(rt => rt.Token)
            .IsUnique()
            .HasDatabaseName("IX_RefreshTokens_Token");

        // ════════════════════════════════════════════════════════════════════════════
        // 5. DATAS DE CONTROLE
        // ════════════════════════════════════════════════════════════════════════════

        // Configura CriadoEm
        // DateTime em UTC (melhor que local time)
        // IsRequired(): obrigatório
        // HasDefaultValueSql("GETUTCDATE()"): banco gera automaticamente
        // Vantagem: mesmo se aplicação enviar tempo errado, banco registra corretamente
        builder.Property(rt => rt.CriadoEm)
            .IsRequired()
            .HasDefaultValueSql("GETUTCDATE()");

        // Índice em CriadoEm
        // Motivo: facilita limpeza de tokens antigos (batch job)
        // Permite encontrar rapidamente tokens criados há mais de 7 dias
        builder.HasIndex(rt => rt.CriadoEm)
            .HasDatabaseName("IX_RefreshTokens_CriadoEm");

        // Configura ExpiraEm
        // DateTime em UTC
        // IsRequired(): obrigatório (sempre tem data de expiração)
        // SEM DefaultValueSql: deve ser calculado na aplicação
        // Motivo: expiração é sempre CriadoEm + 7 dias (lógica de negócio)
        builder.Property(rt => rt.ExpiraEm)
            .IsRequired();

        // Índice em ExpiraEm
        // Motivo: encontrar tokens expirados para limpeza
        // Permite query: WHERE ExpiraEm < GETUTCDATE()
        builder.HasIndex(rt => rt.ExpiraEm)
            .HasDatabaseName("IX_RefreshTokens_ExpiraEm");

        // Configura RevogadoEm
        // DateTime? em UTC (nullable, porque nem sempre é revogado)
        // Sem IsRequired(): nullable (permite NULL)
        // SEM DefaultValue: NULL = ainda não foi revogado
        builder.Property(rt => rt.RevogadoEm)
            .HasColumnType("DATETIME2");

        // ════════════════════════════════════════════════════════════════════════════
        // 6. FLAGS DE CONTROLE
        // ════════════════════════════════════════════════════════════════════════════

        // Configura Revogado
        // bool: true = revogado (não funciona mais), false = ativo
        // IsRequired(): obrigatório (sempre tem um valor)
        // HasDefaultValue(false): novos tokens começam ATIVOS
        builder.Property(rt => rt.Revogado)
            .IsRequired()
            .HasDefaultValue(false);

        // Índice em (IdentityUserId, Revogado)
        // Motivo: encontrar tokens ATIVOS de um usuário
        // Muito comum em: "logout de todas as sessões" = marcar todos como revogado
        // Query: WHERE IdentityUserId = @userId AND Revogado = false
        builder.HasIndex(rt => new { rt.IdentityUserId, rt.Revogado })
            .HasDatabaseName("IX_RefreshTokens_IdentityUserId_Revogado");

        // ════════════════════════════════════════════════════════════════════════════
        // 7. AUDITORIA (IP e User-Agent)
        // ════════════════════════════════════════════════════════════════════════════

        // Configura IpOrigem
        // string? (nullable, pode não ter IP)
        // HasMaxLength(45): IPv6 máximo é ~39 caracteres, mais margem
        // Sem IsRequired(): opcional (não todas as requisições terão IP)
        // Uso: auditoria (de onde veio o login), detecção de anomalias
        builder.Property(rt => rt.IpOrigem)
            .HasMaxLength(45);

        // Configura UserAgent
        // string? (nullable, pode não ter User-Agent)
        // HasMaxLength(500): User-Agent pode ser longo (strings de navegador)
        // Sem IsRequired(): opcional
        // Uso: auditoria (qual app/navegador fez login), detecção de ataque
        // Exemplo: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
        builder.Property(rt => rt.UserAgent)
            .HasMaxLength(500);

    }
}