using Mapster;
using NexusEcommerce.Usuario.Application.DTOs;
using NexusEcommerce.Usuario.Application.Interfaces;
using NexusEcommerce.Usuario.Domain.Entities;
using NexusEcommerce.Usuario.Infrastructure.Data;

namespace NexusEcommerce.Usuario.Infrastructure.Services;

public class ClienteService(ApplicationDbContext context, IConsultaCepService cepService) : IClienteService
{
    public async Task<ClienteResponseDto> CriarClienteAsync(string identityId, string email, CompletarPerfilDto dto)
    {
        // Camada de proteção: consulta externa antes de criar a entidade
        var endereco = await cepService.BuscarEnderecoPorCepAsync(dto.Cep)
            ?? throw new ArgumentException("CEP não encontrado ou inválido.");

        // Domínio executa as regras (Fail-Fast)
        var cliente = new Cliente(identityId, dto.NomeCompleto, dto.Cpf, email);

        cliente.AtribuirEndereco(
            endereco.Cep, endereco.Logradouro, endereco.Bairro,
            endereco.Localidade, endereco.Uf, dto.NumeroEndereco);

        context.Clientes.Add(cliente);
        await context.SaveChangesAsync();

        // Mapster transforma a Entidade rica em um DTO de saída simples
        return cliente.Adapt<ClienteResponseDto>();
    }
}