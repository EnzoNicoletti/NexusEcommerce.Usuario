using NexusEcommerce.Usuario.Application.DTOs;

namespace NexusEcommerce.Usuario.Application.Interfaces;

///<summary>
/// Orquestra o fluxo de criação e gestão de clientes.
///
/// Responsabilidades:
/// - Criar novos clientes com perfil completo
/// - Recuperar clientes por identificadores (IdentityId, Email)
/// - Garantir que operações de cliente sejam consistentes com o banco de dados
///
/// Padrão: Todos os métodos são assincronos (Task-based) para operações de I/O
/// Convenção de Nomes: Métodos que buscam por campo específico usam padrão ObterPor{Campo}
///</summary>
public interface IClienteService
{
    ///<summary>
    /// Cria um novo cliente com os dados de perfil fornecidos.
    ///
    /// Fluxo:
    /// 1. Recebe identityId (referência ao usuário do Identity)
    /// 2. Recebe email já validado (vem do Identity)
    /// 3. Recebe dados complementares via CompletarPerfilDto (nome, cpf, endereço)
    /// 4. Cria instância de Cliente com Role padrão = Cliente
    /// 5. Persiste no banco de dados
    /// 6. Retorna ClienteResponseDto com dados do cliente criado
    ///
    /// Segurança: Email e IdentityId são provenientes do Identity, já validados
    ///
    /// Retorno: ClienteResponseDto com dados do novo cliente criado
    ///</summary>
    Task<ClienteResponseDto> CriarClienteAsync(
        string identityId,
        string email,
        CompletarPerfilDto dto);
    Task<ClienteResponseDto?> ObterPorIdentityIdAsync(string identityId);
    Task<ClienteResponseDto?> ObterPorEmailAsync(string email);
}