using NexusEcommerce.Usuario.Application.DTOs;

namespace NexusEcommerce.Usuario.Application.Interfaces;

/// <summary>
/// Interface para serviços de autenticação
/// </summary>
public interface IAutenticacaoService
{
    /// <summary>
    /// Realiza login do usuário (email e senha)
    /// </summary>
    /// <param name="email">Email do usuário</param>
    /// <param name="senha">Senha do usuário</param>
    /// <param name="ipOrigem">IP da requisição</param>
    /// <param name="userAgent">User Agent do navegador</param>
    /// <returns>Dados de login com tokens</returns>
    Task<LoginResponseDto> LoginAsync(
        string email,
        string senha,
        string? ipOrigem = null,
        string? userAgent = null);

    /// <summary>
    /// Renova o access token usando refresh token
    /// </summary>
    /// <param name="refreshToken">Refresh token válido</param>
    /// <param name="identityId">ID do usuário</param>
    /// <returns>Novo par de tokens</returns>
    Task<RefreshTokenResponseDto> RenovarTokenAsync(
        string refreshToken,
        string identityId);

    /// <summary>
    /// Realiza logout do usuário
    /// </summary>
    /// <param name="refreshToken">Refresh token a revogar</param>
    /// <param name="identityId">ID do usuário</param>
    Task LogoutAsync(string refreshToken, string identityId);

    /// <summary>
    /// Obtém lista paginada de usuários
    /// </summary>
    /// <param name="pagina">Número da página (começando em 1)</param>
    /// <param name="itensPorPagina">Quantidade de itens por página</param>
    /// <returns>Lista paginada de usuários</returns>
    Task<PaginacaoDto<UsuarioPaginadoDto>> ListarUsuariosAsync(
        int pagina = 1,
        int itensPorPagina = 10);

    /// <summary>
    /// Atribui um role (papel) a um usuário
    /// </summary>
    /// <param name="clienteId">ID do cliente</param>
    /// <param name="novoRole">Novo role</param>
    Task AtribuirRoleAsync(Guid clienteId, string novoRole);
}