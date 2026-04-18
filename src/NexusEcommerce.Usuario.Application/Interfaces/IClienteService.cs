using NexusEcommerce.Usuario.Application.DTOs;

namespace NexusEcommerce.Usuario.Application.Interfaces;

/// <summary>
/// Orquestra o fluxo de criação e gestão de clientes.
/// </summary>
public interface IClienteService
{
    Task<ClienteResponseDto> CriarClienteAsync(
        string identityId,
        string email,
        CompletarPerfilDto dto);
}