using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NexusEcommerce.Usuario.API.Models;
using NexusEcommerce.Usuario.Application.Interfaces;
namespace NexusEcommerce.Usuario.API.Controllers;
/// <summary>
/// Controller de Autenticação e Autorização.
///
/// Responsável por gerenciar os 5 fluxos principais de autenticação:
/// 1. Login (gera JWT + Refresh Token)
/// 2. Refresh Token (renova JWT com token rotation)
/// 3. Logout (revoga refresh token)
/// 4. Listar Usuários (com paginação)
/// 5. Atribuir Role (admin only)
///
/// SEGURANÇA:
/// ──────────
/// - JWT em Bearer token (Authorization header)
/// - Refresh tokens armazenados no banco (revocáveis)
/// - Token rotation (cada refresh revoga o token anterior)
/// - Logout real (revogação permanente, não apenas TTL)
/// - Role-based access control (RBAC com 3 roles)
/// - IdentityId sempre extraído do token, nunca do JSON
/// - IP e User-Agent capturados para auditoria
///
/// FLUXO GERAL:
/// ────────────
/// 1. Usuário faz Login → Recebe JWT + Refresh Token
/// 2. Usuário usa JWT para acessar recursos protegidos
/// 3. JWT expira (60 min)
/// 4. Usuário usa Refresh Token para renovar → Recebe novo JWT + novo Refresh
/// 5. Novo Refresh Token revoga o anterior (token rotation)
/// 6. Usuário faz Logout → Refresh Token é revogado
/// 7. Token revogado não funciona mais (logout real)
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize] // Padrão: todos os endpoints requerem autenticação (exceto Login)
public class AuthController(IAutenticacaoService autenticacaoService) : ControllerBase
{
    [HttpPost("login")]
    [AllowAnonymous] // Não requer autenticação para fazer login
    public async Task<IActionResult> Login([FromBody] LoginInputModel model)
    {
        // Validação de modelo
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        try
        {
            // Captura IP da requisição para auditoria
            // Útil para detectar logins de locais incomuns
            var ipOrigem = HttpContext.Connection.RemoteIpAddress?.ToString();

            // Captura User-Agent (navegador/dispositivo)
            // Útil para saber se foi desktop, mobile, qual navegador
            var userAgent = Request.Headers.UserAgent.ToString();

            // Chama serviço de autenticação
            var resultado = await autenticacaoService.LoginAsync(
                model.Email,
                model.Senha,
                ipOrigem,
                userAgent);

            // ✅ Login bem-sucedido
            return Ok(resultado);
        }
        catch (ArgumentException ex)
        {
            // ❌ Email ou senha inválidos
            return BadRequest(new { erro = ex.Message });
        }
        catch (Exception ex)
        {
            // ❌ Erro inesperado
            return StatusCode(500, new { erro = "Erro ao fazer login. Tente novamente mais tarde." });
        }
    }

    [HttpPost("registrar")]
    [AllowAnonymous] // Não requer autenticação para registrar
    public async Task<IActionResult> Registrar([FromBody] RegistrarContaInputModel model)
    {
        // Validação automática via [ApiController]
        // Se ModelState inválido, retorna 400 com detalhes dos erros
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            // Chama serviço de autenticação para registrar novo usuário
            // O serviço encadeia: Identity → Banco → Validações
            var resultado = await autenticacaoService.RegistrarAsync(
                model.Email,
                model.Senha);

            // ✅ Registro bem-sucedido
            // Retorna 200 OK com mensagem de sucesso
            return Ok(resultado);
        }
        catch (ArgumentException ex)
        {
            // ❌ Email duplicado ou dados inválidos
            // Retorna 400 Bad Request com mensagem de erro
            return BadRequest(new { erro = ex.Message });
        }
        catch (Exception ex)
        {
            // ❌ Erro inesperado (banco de dados, rede, etc)
            // Retorna 500 Internal Server Error (genérico por segurança)
            return StatusCode(500, new { erro = "Erro ao registrar. Tente novamente mais tarde." });
        }
    }

    [HttpPost("refresh-token")]
    [Authorize] // Requer access token válido (mesmo que expirado)
    public async Task<IActionResult> RenovarToken([FromBody] RefreshTokenInputModel model)
    {
        // Validação de modelo
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            // 🔐 SEGURANÇA: Extrair IdentityId do token JWT validado
            // NUNCA aceitar ID do JSON (front-end pode falsificar)
            var identityId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

            if (string.IsNullOrEmpty(identityId))
                return Unauthorized(new { erro = "Token inválido." });

            // Chama serviço de renovação com token rotation
            var resultado = await autenticacaoService.RenovarTokenAsync(
                model.RefreshToken,
                identityId);

            // ✅ Renovação bem-sucedida
            return Ok(resultado);
        }
        catch (ArgumentException ex)
        {
            // ❌ Refresh token inválido, expirado ou não encontrado
            return BadRequest(new { erro = ex.Message });
        }
        catch (Exception ex)
        {
            // ❌ Erro inesperado
            return StatusCode(500, new { erro = "Erro ao renovar token. Tente novamente mais tarde." });
        }
    }

    [HttpPost("logout")]
    [Authorize] // Requer autenticação
    public async Task<IActionResult> Logout([FromBody] LogoutInputModel model)
    {
        // Validação de modelo
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            // 🔐 SEGURANÇA: Extrair IdentityId do token JWT validado
            var identityId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

            if (string.IsNullOrEmpty(identityId))
                return Unauthorized(new { erro = "Token inválido." });

            // Chama serviço de logout (revoga refresh token)
            await autenticacaoService.LogoutAsync(
                model.RefreshToken,
                identityId);

            // ✅ Logout bem-sucedido
            return Ok(new { mensagem = "Logout realizado com sucesso." });
        }
        catch (ArgumentException ex)
        {
            // ❌ Refresh token ou usuário não encontrado
            return BadRequest(new { erro = ex.Message });
        }
        catch (Exception ex)
        {
            // ❌ Erro inesperado
            return StatusCode(500, new { erro = "Erro ao fazer logout. Tente novamente mais tarde." });
        }
    }

    [HttpGet("usuarios")]
    [Authorize(Roles = "Administrador,Moderador")] // Apenas admin e moderador
    public async Task<IActionResult> ListarUsuarios(
        [FromQuery] int pagina = 1,
        [FromQuery] int itensPorPagina = 10)
    {
        try
        {
            // Validações de paginação (tratadas pelo serviço também)
            if (pagina < 1) pagina = 1;
            if (itensPorPagina < 1) itensPorPagina = 10;
            if (itensPorPagina > 100) itensPorPagina = 10; // Máximo por segurança

            // Chama serviço de listagem com paginação
            var resultado = await autenticacaoService.ListarUsuariosAsync(pagina, itensPorPagina);

            // ✅ Listagem bem-sucedida
            return Ok(resultado);
        }
        catch (Exception ex)
        {
            // ❌ Erro inesperado
            return StatusCode(500, new { erro = "Erro ao listar usuários. Tente novamente mais tarde." });
        }
    }

    [HttpPost("atribuir-role")]
    [Authorize(Roles = "Administrador")] // Apenas administrador
    public async Task<IActionResult> AtribuirRole([FromBody] AtribuirRoleInputModel model)
    {
        // Validação de modelo
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            // Valida que novo role é um dos valores válidos
            var rolesValidos = new[] { "Cliente", "cliente", "Moderador", "moderador", "Administrador", "administrador" };
            if (!rolesValidos.Contains(model.NovoRole))
                return BadRequest(new { erro = "Role inválido. Use: Cliente, Moderador ou Administrador." });

            // Chama serviço de atribuição de role
            await autenticacaoService.AtribuirRoleAsync(
                model.ClienteId,
                model.NovoRole);

            // ✅ Role atribuído com sucesso
            return Ok(new { mensagem = "Role atribuído com sucesso." });
        }
        catch (ArgumentException ex)
        {
            // ❌ Cliente não encontrado ou dados inválidos
            return NotFound(new { erro = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            // ❌ Operação inválida
            return BadRequest(new { erro = ex.Message });
        }
        catch (Exception ex)
        {
            // ❌ Erro inesperado
            return StatusCode(500, new { erro = "Erro ao atribuir role. Tente novamente mais tarde." });
        }
    }
}
