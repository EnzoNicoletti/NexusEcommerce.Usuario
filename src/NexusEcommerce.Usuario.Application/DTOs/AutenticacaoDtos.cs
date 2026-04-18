namespace NexusEcommerce.Usuario.Application.DTOs;

/// <summary>
/// Resposta retornada após login bem-sucedido
/// </summary>
public record LoginResponseDto(
    string AccessToken,
    string RefreshToken,
    DateTime ExpiracaoAccessToken,
    string Usuario,
    string Role);

/// <summary>
/// Resposta de refresh token
/// </summary>
public record RefreshTokenResponseDto(
    string NovoAccessToken,
    string NovoRefreshToken,
    DateTime ExpiracaoAccessToken);

/// <summary>
/// Usuário para listagem com paginação
/// </summary>
public record UsuarioPaginadoDto(
    Guid Id,
    string NomeCompleto,
    string Email,
    string Cpf,
    string Role,
    DateTime CriadoEm);

/// <summary>
/// Resposta paginada de usuários
/// </summary>
public record PaginacaoDto<T>(
    IEnumerable<T> Itens,
    int PaginaAtual,
    int TotalPaginas,
    int TotalRegistros,
    bool TemProxima,
    bool TemAnterior);