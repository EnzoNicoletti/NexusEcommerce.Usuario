using System.ComponentModel.DataAnnotations;

namespace NexusEcommerce.Usuario.API.Models;

public class RegistrarContaInputModel
{
    [Required(ErrorMessage = "E-mail é obrigatório")]
    [EmailAddress(ErrorMessage = "E-mail com formato inválido")]
    public required string Email { get; set; }

    [Required(ErrorMessage = "Senha é obrigatória")]
    [MinLength(8, ErrorMessage = "A senha deve ter no mínimo 8 caracteres")]
    public required string Senha { get; set; }
}

public class LoginInputModel
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required string Senha { get; set; }
}

public class CompletarPerfilInputModel
{
    [Required] public required string NomeCompleto { get; set; }
    [Required] public required string Cpf { get; set; }
    [Required] public required string Cep { get; set; }
    [Required] public required string NumeroEndereco { get; set; }
}

///<summary>
/// Modelo de entrada para renovação de access token usando refresh token.
///
/// ENDPOINT: POST /api/auth/refresh-token
///
/// Este modelo é utilizado quando o access token expira e o cliente
/// deseja obter um novo token sem fazer login novamente.
///
/// FLUXO:
/// 1. Cliente recebe 401 Unauthorized (access token expirou)
/// 2. Cliente envia este modelo com o refresh token
/// 3. Servidor valida o refresh token no banco
/// 4. Servidor revoga o refresh token antigo (token rotation)
/// 5. Servidor gera novo access token + novo refresh token
/// 6. Cliente armazena novos tokens
///
/// SEGURANÇA:
/// - O access token expirado é enviado no header Authorization
/// - O refresh token é enviado no corpo da requisição
/// - Token rotation: cada refresh revoga o token anterior
/// - Impede reutilização de tokens roubados
///</summary>
public class RefreshTokenInputModel
{
    [Required(ErrorMessage = "Refresh token é obrigatório")]
    public required string RefreshToken { get; set; }
}

///<summary>
/// Modelo de entrada para logout (revogação de refresh token).
///
/// ENDPOINT: POST /api/auth/logout
///
/// Este modelo revoga o refresh token do usuário, impedindo que
/// ele seja reutilizado mesmo que não tenha expirado.
///
/// LOGOUT REAL (não apenas remover do cliente):
/// - Antes: Usuário apaga token do navegador, mas alguém com o token roubado podia usar por 7 dias
/// - Agora: Servidor marca token como revogado no banco, token é inútil
///
/// FLUXO:
/// 1. Usuário clica em "Logout"
/// 2. Cliente envia este modelo com o refresh token
/// 3. Servidor marca o refresh token como revogado
/// 4. Token agora é inútil (revogado no banco)
/// 5. Se alguém tiver o token roubado, não funciona mais
///
/// SEGURANÇA:
/// - O refresh token é revogado no banco (não apenas em memória)
/// - Logout é permanente enquanto o token não expirar (7 dias)
/// - Requer autenticação: usuário deve estar logado para logout
///</summary>
public class LogoutInputModel
{
    [Required(ErrorMessage = "Refresh token é obrigatório")]
    public required string RefreshToken { get; set; }
}

///<summary>
/// Modelo de entrada para atribuição de role a um usuário.
///
/// ENDPOINT: POST /api/auth/atribuir-role
/// AUTORIZAÇÃO: [Authorize(Roles = "Administrador")]
///
/// Apenas administradores podem atribuir roles a usuários.
/// Roles disponíveis: Cliente (0), Moderador (1), Administrador (2)
///
/// FLUXO:
/// 1. Administrador faz requisição POST com ClienteId e NovoRole
/// 2. Servidor valida que o requisitante é administrador
/// 3. Servidor busca cliente no banco
/// 4. Servidor valida se o novo role é válido
/// 5. Servidor atribui novo role ao cliente
/// 6. Servidor salva alteração no banco
///
/// EXEMPLO:
/// POST /api/auth/atribuir-role
/// {
///   "clienteId": "550e8400-e29b-41d4-a716-446655440000",
///   "novoRole": "Moderador"
/// }
///
/// ROLES VÁLIDOS:
/// - "Cliente" (ou "cliente", case-insensitive)
/// - "Moderador" (ou "moderador")
/// - "Administrador" (ou "administrador")
///
/// SEGURANÇA:
/// - Requer [Authorize(Roles = "Administrador")]
/// - Evita escalação de privilégios
/// - Log de auditoria deve registrar quem atribuiu qual role
///</summary>
public class AtribuirRoleInputModel
{
    [Required(ErrorMessage = "ClienteId é obrigatório")]
    public Guid ClienteId { get; set; }

    [Required(ErrorMessage = "Novo role é obrigatório")]
    public required string NovoRole { get; set; }
}