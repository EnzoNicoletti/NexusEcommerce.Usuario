using Mapster;
using Microsoft.EntityFrameworkCore;
using NexusEcommerce.Usuario.Application.DTOs;
using NexusEcommerce.Usuario.Application.Interfaces;
using NexusEcommerce.Usuario.Domain.Entities;
using NexusEcommerce.Usuario.Infrastructure.Data;

namespace NexusEcommerce.Usuario.Infrastructure.Services;

public class ClienteService(ApplicationDbContext context, IConsultaCepService cepService) : IClienteService
{
    ///<summary>
    /// Cria um novo cliente no banco de dados com dados completos de perfil.
    ///
    /// Fluxo:
    /// 1. Valida CEP consultando serviço externo de ViaCEP
    /// 2. Cria entidade Cliente com dados básicos (identityId, nome, cpf, email)
    /// 3. Atribui endereço completo ao cliente
    /// 4. Persiste no DbSet Clientes
    /// 5. Retorna ClienteResponseDto via Mapster
    ///
    /// Exceções:
    /// - ArgumentException: Se CEP não existe ou é inválido
    /// - DbUpdateException: Se falhar ao salvar no banco (duplicatas, restrições, etc)
    ///</summary>
    public async Task<ClienteResponseDto> CriarClienteAsync(string identityId, string email, CompletarPerfilDto dto)
    {
        // Camada de proteção: consulta externa antes de criar a entidade
        // Falha rápido (Fail-Fast) se CEP inválido
        var endereco = await cepService.BuscarEnderecoPorCepAsync(dto.Cep)
            ?? throw new ArgumentException("CEP não encontrado ou inválido.");

        // Domínio executa as regras de negócio (Rich Entity Pattern)
        // Construtor garante que cliente é criado em estado válido
        var cliente = new Cliente(identityId, dto.NomeCompleto, dto.Cpf, email);

        // Método de domínio responsável por validar e aplicar endereço
        cliente.AtribuirEndereco(
            endereco.Cep, endereco.Logradouro, endereco.Bairro,
            endereco.Localidade, endereco.Uf, dto.NumeroEndereco);

        // Registra a entidade no contexto do Entity Framework
        context.Clientes.Add(cliente);

        // Persiste todas as alterações ao banco de dados de forma assincronizada
        await context.SaveChangesAsync();

        // Mapster transforma a Entidade rica em um DTO de saída simples (projeção)
        // DTO contém apenas dados públicos seguros para retornar ao cliente
        return cliente.Adapt<ClienteResponseDto>();
    }

    ///<summary>
    /// Busca um cliente pelo seu IdentityId (identificador do ASP.NET Identity).
    ///
    /// Fluxo:
    /// 1. Consulta o DbSet Clientes filtrando por IdentityId
    /// 2. Se encontrado: mapeia para ClienteResponseDto usando Mapster
    /// 3. Se não encontrado: retorna null (busca legítima que não achou resultado)
    ///
    /// Observação: FirstOrDefaultAsync retorna null se nenhum cliente encontrado
    /// (não lança exceção, permitindo tratamento elegante de "não encontrado")
    ///</summary>
    public async Task<ClienteResponseDto?> ObterPorIdentityIdAsync(string identityId)
    {
        // Busca assincronamente o primeiro (único) cliente com esse IdentityId
        // IdentityId é chave de negócio que vincula ao usuário do Identity
        var cliente = await context.Clientes
            .FirstOrDefaultAsync(c => c.IdentityId == identityId);

        // Se cliente não existe, retorna null (observable difference from error)
        if (cliente == null)
            return null;

        // Mapster transforma entidade Cliente em DTO ClienteResponseDto
        // Projeção de domínio para camada de aplicação (padrão anti-corruption layer)
        return cliente.Adapt<ClienteResponseDto>();
    }

    ///<summary>
    /// Busca um cliente pelo seu email.
    ///
    /// Fluxo:
    /// 1. Consulta o DbSet Clientes filtrando por Email (case-insensitive)
    /// 2. Se encontrado: mapeia para ClienteResponseDto usando Mapster
    /// 3. Se não encontrado: retorna null
    ///
    /// Observação: Email é case-insensitive em HTTP/SMTP standards
    /// EF Core normaliza strings por padrão em SQL Server
    ///
    /// Performance: Email pode ser indexado no banco para melhorar queries
    ///</summary>
    public async Task<ClienteResponseDto?> ObterPorEmailAsync(string email)
    {
        // Busca assincronamente o primeiro (único) cliente com esse email
        // Email é identificador único de usuário (login identifier)
        // EF Core normaliza email em minúsculas automaticamente em SQL Server
        var cliente = await context.Clientes
            .FirstOrDefaultAsync(c => c.Email == email);

        // Se cliente não existe, retorna null (observable difference from error)
        if (cliente == null)
            return null;

        // Mapster transforma entidade Cliente em DTO ClienteResponseDto
        // Projeção de domínio para camada de aplicação (padrão anti-corruption layer)
        return cliente.Adapt<ClienteResponseDto>();
    }
}