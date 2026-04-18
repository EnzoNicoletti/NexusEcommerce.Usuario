using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NexusEcommerce.Usuario.Application.DTOs;
using NexusEcommerce.Usuario.Application.Interfaces;
using NexusEcommerce.Usuario.Domain.Entities;
using NexusEcommerce.Usuario.Domain.Enums;
using NexusEcommerce.Usuario.Domain.Exceptions;
using NexusEcommerce.Usuario.Infrastructure.Data;

namespace NexusEcommerce.Usuario.Infrastructure.Services;

public class AutenticacaoService(
UserManager<IdentityUser> userManager,
ApplicationDbContext context,
IClienteService clienteService,
ITokenService tokenService) : IAutenticacaoService
{
    public async Task<LoginResponseDto> LoginAsync(
    string email,
    string senha,
    string? ipOrigem,
    string? userAgent)
    {
        // Valida credenciais no [ASP.NET](http://asp.net/) Identity
        // UserManager.FindByEmailAsync: busca usuário por email normalizado
        // O Identity normaliza emails para lowercase automaticamente
        var identityUser = await userManager.FindByEmailAsync(email)
        ?? throw new DomainException("Email ou senha incorretos");
        // Valida senha comparando com hash bcrypt armazenado
        // CheckPasswordAsync: faz hash da senha informada e compara com hash no banco
        // Retorna false se senha incorreta (sem revelar qual erro exato)
        var passwordValid = await userManager.CheckPasswordAsync(identityUser, senha);
        if (!passwordValid)
            throw new DomainException("Email ou senha incorretos");

        // Busca Cliente (entidade de negócio) associado ao IdentityUser
        // ClienteService.ObterPorEmailAsync: consulta Clientes por email
        // Retorna null se Cliente não existir (usuário incompleto)
        var cliente = await clienteService.ObterPorEmailAsync(email)
            ?? throw new DomainException("Cliente não encontrado");

        // Gera Access Token (JWT)
        // TokenService.GerarAccessToken: cria JWT com claims (sub, email, role)
        // TTL: 60 minutos (configurável em appsettings.json)
        // Assinado com HMACSHA256
        var accessToken = tokenService.GerarAccessToken(
            identityUser.Id,      // sub (subject = identificador do usuário)
            identityUser.Email!,  // email claim
            (UserRole)Enum.Parse(typeof(UserRole), cliente.Role));  // role claim (para autorização)

        // Gera Refresh Token (aleatório e seguro)
        // TokenService.GerarRefreshToken: cria 32 bytes aleatórios (256 bits)
        // Convertidos para Base64
        var refreshToken = tokenService.GerarRefreshToken();

        // Cria entidade RefreshToken para armazenar no banco
        // RefreshToken entity:
        // - Id: GUID único
        // - Token: token aleatório (armazenado em plaintext, pode ser hasheado futuramente)
        // - IdentityUserId: FK para IdentityUser
        // - CriadoEm: DateTime.UtcNow (quando foi criado)
        // - ExpiraEm: 7 dias no futuro
        // - Revogado: false (ainda ativo)
        // - IpOrigem, UserAgent: auditoria
        var refreshTokenEntity = new RefreshToken
        {
            // Id = Guid.NewGuid() é feito no construtor padrão
            IdentityUserId = identityUser.Id,
            Token = refreshToken,
            CriadoEm = DateTime.UtcNow,

            // TTL: 7 dias (pode ser configurável)
            // Refresh token tem TTL longo para permite renovação por até 7 dias
            ExpiraEm = DateTime.UtcNow.AddDays(7),

            // Flags de controle
            Revogado = false,      // Ainda ativo (não foi feito logout)
            RevogadoEm = null,     // Não foi revogado ainda

            // Auditoria
            IpOrigem = ipOrigem,
            UserAgent = userAgent
        };

        // Persiste Refresh Token no banco
        // AddAsync: registra nova entidade no DbSet
        // SaveChangesAsync: executa INSERT no banco
        context.RefreshTokens.Add(refreshTokenEntity);
        await context.SaveChangesAsync();

        // Calcula tempo de expiração do access token
        // 60 minutos no futuro (mesmo que configurado no TokenService)
        var expiracaoAccessToken = DateTime.UtcNow.AddMinutes(60);

        // Retorna resposta de login bem-sucedido
        // LoginResponseDto: contém todos os tokens e informações do usuário
        return new LoginResponseDto(
            AccessToken: accessToken,
            RefreshToken: refreshToken,
            ExpiracaoAccessToken: expiracaoAccessToken,
            Usuario: cliente.NomeCompleto,
            Role: cliente.Role.ToString());  // "Cliente", "Moderador", "Administrador"
    }

    public async Task<RefreshTokenResponseDto> RenovarTokenAsync(
        string refreshToken,
        string identityId)
    {
        // Valida refresh token no banco
        // TokenService.ValidarRefreshTokenAsync: verifica:
        // - Token existe?
        // - Não foi revogado?
        // - Não expirou?
        // Retorna true se OK, false se inválido
        var isValidRefreshToken = await tokenService.ValidarRefreshTokenAsync(
            refreshToken,
            identityId);

        // Se refresh token é inválido, nega a renovação
        // Cliente precisa fazer login de novo
        if (!isValidRefreshToken)
            throw new DomainException("Refresh token inválido, expirado ou revogado. Faça login novamente.");

        // Busca Cliente por IdentityId
        // ClienteService.ObterPorIdentityIdAsync: consulta Clientes por identityId
        // Retorna dados do cliente (email, role, nome)
        var cliente = await clienteService.ObterPorIdentityIdAsync(identityId)
            ?? throw new DomainException("Cliente não encontrado");

        // REVOGA refresh token antigo (Token Rotation - segurança)
        // TokenService.RevogarRefreshTokenAsync: marca como revogado no banco
        // Resultado: token antigo nunca mais funciona
        // Efeito: se token foi roubado, fica inútil após usar uma vez
        await tokenService.RevogarRefreshTokenAsync(refreshToken, identityId);

        // Gera novo Access Token (JWT com 60 min TTL)
        // TokenService.GerarAccessToken: cria novo JWT
        // Claims: sub (identityId), email, role, exp, iat, etc
        var novoAccessToken = tokenService.GerarAccessToken(
            identityId,
            cliente.Email,
            (UserRole)Enum.Parse(typeof(UserRole), cliente.Role));

        // Gera novo Refresh Token (256 bits aleatórios)
        // TokenService.GerarRefreshToken: cria novo token aleatório
        // Base64 encoded
        var novoRefreshToken = tokenService.GerarRefreshToken();

        // Cria nova entidade RefreshToken para armazenar no banco
        var novoRefreshTokenEntity = new RefreshToken
        {
            IdentityUserId = identityId,
            Token = novoRefreshToken,
            CriadoEm = DateTime.UtcNow,
            ExpiraEm = DateTime.UtcNow.AddDays(7),
            Revogado = false,
            RevogadoEm = null,
            IpOrigem = null,      // Poderia capturar IP de HttpContext
            UserAgent = null      // Poderia capturar User-Agent
        };

        // Persiste novo Refresh Token no banco
        context.RefreshTokens.Add(novoRefreshTokenEntity);
        await context.SaveChangesAsync();

        // Calcula expiração do novo access token
        var expiracaoAccessToken = DateTime.UtcNow.AddMinutes(60);

        // Retorna novos tokens
        return new RefreshTokenResponseDto(
            NovoAccessToken: novoAccessToken,
            NovoRefreshToken: novoRefreshToken,
            ExpiracaoAccessToken: expiracaoAccessToken);
    }
    public async Task LogoutAsync(string refreshToken, string identityId)
    {
        // Revoga refresh token
        // TokenService.RevogarRefreshTokenAsync: marca como revogado no banco
        // Resultado:
        // - Revogado = true
        // - RevogadoEm = DateTime.UtcNow
        // - Token fica inutilizável
        await tokenService.RevogarRefreshTokenAsync(refreshToken, identityId);

        // Logout concluído
        // Não precisa fazer mais nada
        // Cliente apagará tokens locais
        // Próxima requisição sem Authorization header será rejeitada (401)
    }

    public async Task<PaginacaoDto<UsuarioPaginadoDto>> ListarUsuariosAsync(
        int pagina,
        int itensPorPagina)
    {
        // Valida parâmetros de paginação
        if (pagina < 1)
            throw new ArgumentException("Página deve ser >= 1", nameof(pagina));
        if (itensPorPagina <= 0)
            throw new ArgumentException("Itens por página deve ser > 0", nameof(itensPorPagina));

        // Conta total de clientes no banco
        // CountAsync: executa COUNT(*) no SQL
        // Sem filtro: conta TODOS os clientes
        var totalRegistros = await context.Clientes.CountAsync();

        // Calcula total de páginas
        // Fórmula: (totalRegistros + itensPorPagina - 1) / itensPorPagina
        // Exemplo: 25 registros, 10 por página
        // (25 + 10 - 1) / 10 = 34 / 10 = 3 páginas (arredonda para cima)
        var totalPaginas = (totalRegistros + itensPorPagina - 1) / itensPorPagina;

        // Calcula quantos registros pular (Skip)
        // Fórmula: (pagina - 1) * itensPorPagina
        // Exemplo: página 2, 10 por página
        // (2 - 1) * 10 = 10 (pula 10 registros, começa no 11º)
        var skip = (pagina - 1) * itensPorPagina;

        // Busca clientes da página especificada
        // Skip(skip): pula X registros
        // Take(itensPorPagina): pega Y registros
        // ToListAsync: executa query no banco (assincronamente)
        var clientes = await context.Clientes
            .Skip(skip)
            .Take(itensPorPagina)
            .ToListAsync();

        // Mapeia Cliente → UsuarioPaginadoDto
        // Mapster: transforma entidade de domínio em DTO de aplicação
        // DTO contém apenas dados públicos (sem dados internos)
        var usuariosDtos = clientes
            .Select(c => c.Adapt<UsuarioPaginadoDto>())
            .ToList();

        // Calcula flags de navegação
        // TemProxima: existe página após esta?
        var temProxima = pagina < totalPaginas;

        // TemAnterior: existe página antes desta?
        var temAnterior = pagina > 1;

        // Retorna resultado paginado
        return new PaginacaoDto<UsuarioPaginadoDto>(
            Itens: usuariosDtos,
            PaginaAtual: pagina,
            TotalPaginas: totalPaginas,
            TotalRegistros: totalRegistros,
            TemProxima: temProxima,
            TemAnterior: temAnterior);
    }

    public async Task AtribuirRoleAsync(Guid clienteId, string novoRole)
    {
        // Valida que novoRole é um valor válido do enum UserRole
        // Enum.TryParse: tenta converter string para enum
        // Terceiro parâmetro true: ignora case (maiúsculas/minúsculas)
        // out var role: retorna o enum se conversão bem-sucedida
        var isValidRole = Enum.TryParse<UserRole>(
            novoRole,
            ignoreCase: true,
            out var role);

        // Se role é inválido, nega a operação
        if (!isValidRole)
            throw new ArgumentException(
                $"Role '{novoRole}' é inválido. Valores válidos: Cliente, Moderador, Administrador",
                nameof(novoRole));

        // Busca Cliente por ID
        // FirstOrDefaultAsync: retorna primeiro ou null
        // WHERE Cliente.Id == clienteId
        var cliente = await context.Clientes
            .FirstOrDefaultAsync(c => c.Id == clienteId)
            ?? throw new DomainException("Cliente não encontrado");

        // Atribui novo role (método de domínio)
        // Cliente.AtribuirRole: valida no domínio se role é diferente do atual
        // Lança DomainException se role é igual ao atual
        cliente.AtribuirRole(role);

        // Marca entidade como modificada
        // EF Core normalmente rastreia mudanças automaticamente
        // Explícito: deixa clara a intenção
        context.Clientes.Update(cliente);

        // Persiste mudança no banco
        // SaveChangesAsync: executa UPDATE Cliente SET Role = @role WHERE Id = @id
        await context.SaveChangesAsync();
    }

}
