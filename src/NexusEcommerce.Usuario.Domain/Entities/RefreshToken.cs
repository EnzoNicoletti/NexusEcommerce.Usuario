namespace NexusEcommerce.Usuario.Domain.Entities;

/// <summary>
/// Representa um token de atualização (refresh token) armazenado no banco
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Referência ao usuário Identity do ASP.NET Core</summary>
    public string IdentityUserId { get; set; } = string.Empty;

    /// <summary>Token criptografado/hash</summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>Quando o token foi criado</summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;

    /// <summary>Quando o token expira</summary>
    public DateTime ExpiraEm { get; set; }

    /// <summary>Se foi revogado (logout)</summary>
    public bool Revogado { get; set; }

    /// <summary>Quando foi revogado</summary>
    public DateTime? RevogadoEm { get; set; }

    /// <summary>Endereço IP de origem (auditoria)</summary>
    public string? IpOrigem { get; set; }

    /// <summary>User Agent (auditoria)</summary>
    public string? UserAgent { get; set; }
}