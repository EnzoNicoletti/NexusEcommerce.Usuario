namespace NexusEcommerce.Usuario.Domain.Enums;

/// <summary>
/// Define os papéis (roles) disponíveis no sistema Nexus Ecommerce
/// </summary>
public enum UserRole
{
    /// <summary>Cliente padrão da plataforma</summary>
    Cliente = 0,

    /// <summary>Gerenciador de conteúdo e suporte</summary>
    Moderador = 1,

    /// <summary>Administrador do sistema</summary>
    Administrador = 2
}