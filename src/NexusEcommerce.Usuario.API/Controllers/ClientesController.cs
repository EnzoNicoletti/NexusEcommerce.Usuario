using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NexusEcommerce.Usuario.API.Models;
using NexusEcommerce.Usuario.Application.DTOs;
using NexusEcommerce.Usuario.Application.Interfaces;
using NexusEcommerce.Usuario.Domain.Exceptions;

namespace NexusEcommerce.Usuario.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize] // Bloqueia acesso sem Token JWT
// Controller injeta INTERFACE (Application) — nunca DbContext diretamente!
public class ClientesController(IClienteService service) : ControllerBase
{
    [HttpPost("completar-perfil")]
    public async Task<IActionResult> CompletarPerfil([FromBody] CompletarPerfilInputModel model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        // A REGRA DE OURO DA SEGURANÇA:
        // Nunca confie no ID vindo do JSON (front-end). Extraia sempre do Token validado.
        var identityId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var email = User.FindFirstValue(ClaimTypes.Email)!;

        var dto = new CompletarPerfilDto(
            model.NomeCompleto, model.Cpf,
            model.Cep, model.NumeroEndereco);

        try
        {
            var result = await service.CriarClienteAsync(identityId, email, dto);
            return Ok(new { Mensagem = "Perfil completado com sucesso!", Dados = result });
        }
        catch (DomainException ex)
        {
            // Erro de regra de negócio (Ex: CPF Inválido) → 400 Bad Request
            return BadRequest(new { Erro = ex.Message });
        }
        catch (ArgumentException ex)
        {
            // Erro de argumento (Ex: CEP não encontrado no ViaCEP) → 400 Bad Request
            return BadRequest(new { Erro = ex.Message });
        }
        catch (DbUpdateException ex) when (ex.InnerException?.Message.Contains("IX_Clientes_Cpf_Unico") == true)
        {
            // Índice único violado no Banco de Dados → 409 Conflict
            return Conflict(new { Erro = "Este CPF já está cadastrado em nossa base." });
        }
    }
}