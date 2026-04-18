using NexusEcommerce.Usuario.Application.DTOs;

namespace NexusEcommerce.Usuario.Application.Interfaces;

/// <summary>
/// Contrato para serviços de busca de endereço (Anti-Corruption Layer).
/// </summary>
public interface IConsultaCepService
{
    Task<EnderecoDto?> BuscarEnderecoPorCepAsync(string cep);
}