using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NexusEcommerce.Usuario.API.Models;

namespace NexusEcommerce.Usuario.API.Controllers;

[ApiController]
[Route("api/[controller]")]
// Primary Constructor injeta as dependências direto na declaração da classe
public class ContaController(UserManager<IdentityUser> userManager, IConfiguration config) : ControllerBase
{
    [HttpPost("registrar")]
    public async Task<IActionResult> Registrar([FromBody] RegistrarContaInputModel model)
    {
        // O ASP.NET já faz validação automática com o [ApiController], mas mantemos
        // para garantir caso algum filtro global seja alterado futuramente.
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = new IdentityUser { UserName = model.Email, Email = model.Email };
        var result = await userManager.CreateAsync(user, model.Senha);

        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok(new { Mensagem = "Conta criada com sucesso! Complete seu perfil para realizar compras." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginInputModel model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = await userManager.FindByEmailAsync(model.Email);

        if (user is null || !await userManager.CheckPasswordAsync(user, model.Senha))
            return Unauthorized(new { Erro = "Credenciais inválidas." });

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(ClaimTypes.NameIdentifier, user.Id), // Crucial para o User.FindFirstValue()
            new Claim(ClaimTypes.Email, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Secret"]!));

        var token = new JwtSecurityToken(
            issuer: config["Jwt:Issuer"],
            audience: config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        );

        return Ok(new
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            Expiracao = token.ValidTo
        });
    }
}