using NexusEcommerce.Usuario.Domain.Enums;

namespace NexusEcommerce.Usuario.Application.Interfaces;

/// <summary>
/// Interface para geração e validação de tokens JWT
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Gera um novo access token JWT
    /// </summary>
    /// <param name="identityId">ID do usuário no Identity</param>
    /// <param name="email">Email do usuário</param>
    /// <param name="role">Papel do usuário</param>
    /// <returns>Token JWT</returns>
    string GerarAccessToken(string identityId, string email, UserRole role);

    /// <summary>
    /// Gera um novo refresh token aleatório
    /// </summary>
    /// <returns>Refresh token (aleatório e seguro)</returns>
    string GerarRefreshToken();

    /// <summary>
    /// Valida um refresh token
    /// </summary>
    /// <param name="token">Token a validar</param>
    /// <returns>Verdadeiro se válido</returns>
    Task<bool> ValidarRefreshTokenAsync(string token, string identityId);

    /// <summary>
    /// Revoga um refresh token (logout)
    /// </summary>
    /// <param name="token">Token a revogar</param>
    /// <param name="identityId">ID do usuário</param>
    Task RevogarRefreshTokenAsync(string token, string identityId);
}