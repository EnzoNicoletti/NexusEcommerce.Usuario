using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NexusEcommerce.Usuario.Application.Interfaces;
using NexusEcommerce.Usuario.Domain.Enums;
using NexusEcommerce.Usuario.Infrastructure.Data;

namespace NexusEcommerce.Usuario.Infrastructure.Services;

/// <summary>
/// Implementação concreta de ITokenService.
/// 
/// Responsabilidades:
/// 1. Gerar JWT (Access Tokens) assinados com chave secreta
/// 2. Gerar Refresh Tokens aleatórios e seguros
/// 3. Validar Refresh Tokens consultando o banco de dados
/// 4. Revogar Refresh Tokens (logout e token rotation)
/// 
/// Segurança:
/// - Chave secreta vem do IConfiguration (Secret Manager ou env vars)
/// - Nunca armazenado em código-fonte
/// - Mínimo 32 caracteres (256 bits) para HMACSHA256
/// - Mesmo em todos os servidores (para validação consistente)
/// 
/// Padrão: Dependency Injection
/// - Injetado como ITokenService (interface, não implementação)
/// - Consumido por IAutenticacaoService
/// </summary>
public class TokenService(
    ApplicationDbContext context,
    IConfiguration configuration) : ITokenService
{
    /// <summary>
    /// Chave secreta para assinar JWT.
    /// 
    /// Leitura: configuration["JwtSettings:SecretKey"]
    /// Origem: appsettings.json, Secret Manager, ou variável ambiente
    /// 
    /// Requisito: Mínimo 32 caracteres (256 bits)
    /// 
    /// Nunca compartilhe essa chave (é secreta mesmo!)
    /// Geração de exemplo (no PowerShell):
    /// [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Guid]::NewGuid().ToString() + [System.Guid]::NewGuid().ToString()))
    /// 
    /// Armazene em:
    /// - Desenvolvimento: dotnet user-secrets
    /// - Produção: Azure Key Vault, AWS Secrets Manager, etc
    /// </summary>
    private readonly string _secretKey = configuration["JwtSettings:SecretKey"]
        ?? throw new InvalidOperationException("JwtSettings:SecretKey não configurado em appsettings.json");

    /// <summary>
    /// Tempo de expiração do Access Token em minutos.
    /// 
    /// Padrão: 60 minutos
    /// 
    /// Leitura: configuration["JwtSettings:ExpiracaoEmMinutos"]
    /// Fallback: 60 se não especificado
    /// 
    /// Considerações:
    /// - Muito curto (15 min): usuário precisa renovar frequentemente (ruim UX)
    /// - Ideal (60 min): equilíbrio entre segurança e UX
    /// - Muito longo (24 horas): muito tempo exposto se roubado (ruim segurança)
    /// </summary>
    private readonly int _expiracaoEmMinutos = int.Parse(
        configuration["JwtSettings:ExpiracaoEmMinutos"] ?? "60");

    /// <summary>
    /// Nome do emissor do JWT.
    /// 
    /// Padrão: "NexusEcommerce"
    /// 
    /// Leitura: configuration["JwtSettings:Issuer"]
    /// Fallback: "NexusEcommerce" se não especificado
    /// 
    /// Incluído no JWT como claim "iss"
    /// Validado durante autenticação (deve conferir)
    /// </summary>
    private readonly string _issuer = configuration["JwtSettings:Issuer"]
        ?? "NexusEcommerce";

    /// <summary>
    /// Público-alvo do JWT.
    /// 
    /// Padrão: "NexusEcommerceUsers"
    /// 
    /// Leitura: configuration["JwtSettings:Audience"]
    /// Fallback: "NexusEcommerceUsers" se não especificado
    /// 
    /// Incluído no JWT como claim "aud"
    /// Validado durante autenticação (deve conferir)
    /// 
    /// Uso: Se sua app gera tokens para diferentes públicos,
    /// você pode ter audiences diferentes (ex: "API", "Web", "Mobile")
    /// </summary>
    private readonly string _audience = configuration["JwtSettings:Audience"]
        ?? "NexusEcommerceUsers";

    /// <summary>
    /// Gera um novo JWT (JSON Web Token) para autorizar requisições.
    /// 
    /// ESTRUTURA DO JWT:
    /// ──────────────────
    /// header.payload.signature
    /// 
    /// Exemplo decodificado:
    /// 
    /// HEADER:
    /// {
    ///   "alg": "HS256",
    ///   "typ": "JWT"
    /// }
    /// 
    /// PAYLOAD:
    /// {
    ///   "sub": "user-123",                    // subject (quem é)
    ///   "email": "joao@example.com",          // email
    ///   "role": "Moderador",                  // role como string
    ///   "role_value": "1",                    // role como número (0, 1, 2)
    ///   "iat": 1681379445,                    // issued at (Unix timestamp)
    ///   "exp": 1681383045,                    // expiration (Unix timestamp)
    ///   "iss": "NexusEcommerce",              // issuer
    ///   "aud": "NexusEcommerceUsers"          // audience
    /// }
    /// 
    /// SIGNATURE:
    /// HMACSHA256(base64(header) + "." + base64(payload), secret_key)
    /// 
    /// JWT FINAL (truncado):
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJeU...
    /// 
    /// FLUXO:
    /// 1. Servidor cria JWT assinando com chave secreta
    /// 2. Cliente armazena JWT (localStorage, memory, sessionStorage)
    /// 3. Cliente envia em cada requisição: Authorization: Bearer {jwt}
    /// 4. Servidor valida JWT decodificando e verificando assinatura
    /// 5. Se assinatura OK e não expirou, requisição é processada
    /// 
    /// SEGURANÇA IMPORTANTE:
    /// ────────────────────
    /// - JWT não é criptografado (é Base64, que é codificação, não criptografia)
    /// - Qualquer um consegue decodificar e ler o conteúdo
    /// - A segurança vem da ASSINATURA (só quem tem a chave secreta consegue assinar)
    /// - Por isso NUNCA colocar dados confidenciais no JWT
    /// 
    /// VALIDAÇÃO:
    /// ──────────
    /// Quando JWT é recebido:
    /// 1. Divide em header.payload.signature
    /// 2. Decodifica header e payload (qualquer um consegue)
    /// 3. Regenera a assinatura usando a chave secreta
    /// 4. Compara assinatura recebida com gerada
    /// 5. Se forem diferentes = alguém alterou o JWT = REJEITA
    /// 6. Se forem iguais = JWT é válido
    /// 7. Valida exp (não expirou?), iss, aud, etc
    /// </summary>
    /// <param name="identityId">
    /// ID do usuário no ASP.NET Core Identity.
    /// 
    /// Tipo: string (GUID formatado)
    /// Exemplo: "550e8400-e29b-41d4-a716-446655440000"
    /// Origem: IdentityUser.Id
    /// 
    /// Será incluído como claim "sub" (subject) no JWT
    /// Identificador único do usuário no sistema
    /// </param>
    /// <param name="email">
    /// Email do usuário.
    /// 
    /// Tipo: string
    /// Exemplo: "joao@example.com"
    /// Origem: IdentityUser.Email (já normalizado para minúsculas)
    /// 
    /// Será incluído como claim "email" no JWT
    /// Usado para exibição e identificação
    /// </param>
    /// <param name="role">
    /// Papel do usuário no sistema (enum UserRole).
    /// 
    /// Tipo: UserRole (enum)
    /// Valores: Cliente (0), Moderador (1), Administrador (2)
    /// Origem: Cliente.Role
    /// 
    /// Será incluído no JWT como:
    /// - "role" = string do role (ex: "Moderador")
    /// - "role_value" = valor numérico do role (ex: "1")
    /// 
    /// O middleware/controllers usam role do JWT para autorizar:
    /// [Authorize(Roles = "Administrador,Moderador")]
    /// public async Task<IActionResult> ListarUsuarios() { ... }
    /// </param>
    /// <returns>
    /// String contendo o JWT completo (header.payload.signature).
    /// 
    /// Formato: Base64URL-encoded
    /// Tamanho: Tipicamente 300-500 caracteres
    /// 
    /// Exemplo (muito truncado):
    /// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJlbWFpbCI6Impvh..."
    /// 
    /// Este token deve ser:
    /// 1. Enviado para o cliente no LoginResponseDto
    /// 2. Armazenado no cliente (localStorage, memory, etc)
    /// 3. Enviado em cada requisição no header Authorization
    /// 4. Validado pelo middleware de autenticação antes de processar
    /// </returns>
    public string GerarAccessToken(string identityId, string email, UserRole role)
    {
        // Cria a chave de segurança a partir da string secreta
        // 1. Codifica a string secreta para bytes UTF-8
        var keyBytes = System.Text.Encoding.UTF8.GetBytes(_secretKey);

        // 2. Cria SymmetricSecurityKey (chave para algoritmo HMACSHA256)
        // SymmetricSecurityKey usa a mesma chave para assinar e validar
        var securityKey = new SymmetricSecurityKey(keyBytes);

        // Cria as credenciais de assinatura
        // 1. Especifica algoritmo (HMACSHA256)
        // 2. Usa a chave de segurança criada acima
        // SigningCredentials = prova que somos quem dizemos ser (assinatura criptográfica)
        var signingCredentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.HmacSha256Signature);

        // Define claims (declarações sobre o usuário)
        // Claims = dados inclusos no JWT (identificação e autorização)
        var claims = new List<Claim>
        {
            // "sub" (subject): Identificador único do usuário (padrão JWT RFC 7519)
            // NameIdentifier é o tipo de claim padrão para "sub"
            new(ClaimTypes.NameIdentifier, identityId),
            
            // "email": Email do usuário (identificação)
            // Padrão para email em System.Security.Claims
            new(ClaimTypes.Email, email),
            
            // "role": Nome do role como string (ex: "Moderador")
            // Para usar com [Authorize(Roles = "Moderador")]
            new(ClaimTypes.Role, role.ToString()),
            
            // "role_value": Valor numérico do role (0, 1, 2)
            // Otimização: valores numéricos são mais rápidos que strings em validações
            new("role_value", ((int)role).ToString()),
        };

        // Calcula o tempo de expiração
        // 1. Obtém horário atual em UTC
        // 2. Adiciona _expiracaoEmMinutos (padrão 60)
        // 3. Resultado: JWT válido por 60 minutos
        var expiracaoEm = DateTime.UtcNow.AddMinutes(_expiracaoEmMinutos);

        // Cria o JWT (não é string ainda, é um objeto JwtSecurityToken)
        // Define a estrutura completa do token
        var token = new JwtSecurityToken(
            issuer: _issuer,              // "iss": quem criou este token
            audience: _audience,          // "aud": para quem este token é
            claims: claims,               // dados do usuário (sub, email, role)
            expires: expiracaoEm,         // "exp": quando expira (Unix timestamp)
            signingCredentials: signingCredentials);  // assinatura criptográfica

        // Converte o JwtSecurityToken em string
        // JwtSecurityTokenHandler faz a serialização para formato Base64URL
        var tokenHandler = new JwtSecurityTokenHandler();

        // WriteToken: transforma JwtSecurityToken em string Base64URL
        // Resultado: "header.payload.signature" pronto para enviar ao cliente
        var tokenString = tokenHandler.WriteToken(token);

        // Retorna o JWT como string
        // Cliente receberá isso e armazenará (localStorage, etc)
        return tokenString;
    }

    /// <summary>
    /// Gera um novo refresh token aleatório e seguro.
    /// 
    /// DIFERENÇA ENTRE ACCESS TOKEN E REFRESH TOKEN:
    /// ──────────────────────────────────────────────
    /// 
    /// Access Token (JWT):
    /// - Contém dados do usuário (claims)
    /// - Criptografado e assinado
    /// - TTL curto: 60 minutos
    /// - Usado a CADA requisição (Authorization header)
    /// - Não armazenado no banco
    /// - Stateless: não precisa consultar banco para validar
    /// 
    /// Refresh Token (aleatório):
    /// - String aleatória simples
    /// - Sem dados, apenas identificador
    /// - TTL longo: 7 dias
    /// - Usado APENAS para gerar novo access token
    /// - Armazenado NO BANCO (importante!)
    /// - Stateful: precisa consultar banco para validar
    /// 
    /// POR QUE DOIS TOKENS?
    /// ────────────────────
    /// 
    /// Cenário 1: Usar um token com 7 dias
    /// Problemas:
    /// - Muita exposição: se roubado, fica válido por 7 dias
    /// - Logout não funciona: continua válido até expirar
    /// - Sem possibilidade de revogação
    /// 
    /// Cenário 2: Usar JWT + Refresh (nosso caso)
    /// Benefícios:
    /// - Access token curto (60 min): menos exposição
    /// - Refresh token longo (7 dias): renovação automática sem login
    /// - Logout funciona: marca refresh como revogado
    /// - Token rotation: cada refresh cria novo token, revoga antigo
    /// - Melhor trade-off entre segurança e UX
    /// 
    /// FLUXO:
    /// ──────
    /// 1. Usuário faz login
    /// 2. Servidor emite: AccessToken (60 min) + RefreshToken (7 dias)
    /// 3. Usuário usa AccessToken para requisições (60 minutos)
    /// 4. Quando AccessToken expira:
    ///    a. Cliente detecta (401 Unauthorized)
    ///    b. Cliente envia RefreshToken para renovar
    ///    c. Servidor valida RefreshToken no banco
    ///    d. Se OK: emite novo AccessToken (60 min) + novo RefreshToken (7 dias)
    ///    e. Cliente usa novo AccessToken
    /// 5. Processo se repete até RefreshToken expirar (7 dias)
    /// 6. Se RefreshToken expira: usuário precisa fazer login de novo
    /// 
    /// GERAÇÃO SEGURA:
    /// ───────────────
    /// 1. Cria array de 32 bytes
    /// 2. Usa RandomNumberGenerator (CSPRNG = Cryptographically Secure Pseudo-Random Number Generator)
    /// 3. Preenche array com bytes aleatórios criptograficamente seguros
    /// 4. Converte para Base64 (43-44 caracteres)
    /// 5. Cada chamada gera novo token único
    /// 6. Computacionalmente impossível adivinhar ou repetir
    /// 
    /// EXEMPLO:
    /// ────────
    /// Array de 32 bytes preenchido com aleatoriedade:
    /// [0x3E, 0x7D, 0x42, 0xAF, 0x1B, 0x8C, 0x59, 0xD2, ...]
    /// 
    /// Convertido para Base64:
    /// "PH1CrxuMWdIvT8m9lK2pqR3sTuVwXyZaBcDeFgHiJkL="
    /// (43 caracteres = 32 bytes em Base64)
    /// </summary>
    /// <returns>
    /// String aleatória segura em Base64.
    /// 
    /// Características:
    /// - 32 bytes (256 bits) de aleatoriedade
    /// - Convertido para Base64 (43-44 caracteres)
    /// - Cada chamada gera novo token
    /// - Nunca repete (probabilidade negligenciável)
    /// 
    /// Exemplo: "PH1CrxuMWdIvT8m9lK2pqR3sTuVwXyZaBcDeFgHiJkL="
    /// 
    /// Este token será:
    /// 1. Salvo no banco de dados (RefreshTokens table)
    /// 2. Incluído na LoginResponseDto
    /// 3. Armazenado no cliente (localStorage, memory, etc)
    /// 4. Enviado para /api/auth/refresh-token quando access token expirar
    /// 5. Armazenado em RefreshToken entity com metadata (CriadoEm, ExpiraEm, IP, UserAgent)
    /// </returns>
    public string GerarRefreshToken()
    {
        // Cria array para armazenar bytes aleatórios
        // 32 bytes = 256 bits de entropia
        // Quanto maior, mais seguro, mas também maior o token
        // 32 é o padrão recomendado para tokens (256 bits)
        var randomBytes = new byte[32];

        // Usa RandomNumberGenerator (CSPRNG - Cryptographically Secure)
        // Diferente de Random (não seguro para criptografia)
        // 
        // IMPORTANTE: usando 'using' garante liberação de recursos
        // RandomNumberGenerator implementa IDisposable
        using (var rng = RandomNumberGenerator.Create())
        {
            // Preenche o array com bytes aleatórios criptograficamente seguros
            // GetBytes é thread-safe e cryptographically secure
            // Cada byte é preenchido com valor aleatório entre 0-255
            rng.GetBytes(randomBytes);
        }

        // Converte array de bytes para string Base64
        // Base64 usa apenas caracteres seguros (a-z, A-Z, 0-9, +, /, =)
        // Permite transmitir dados binários como string
        // 32 bytes → 43-44 caracteres em Base64
        var base64Token = Convert.ToBase64String(randomBytes);

        // Retorna o token aleatório como string
        // Cliente receberá isso e armazenará
        return base64Token;
    }

    /// <summary>
    /// Valida se um refresh token é válido e ainda está ativo.
    /// 
    /// VALIDAÇÕES REALIZADAS:
    /// ──────────────────────
    /// 1. Token existe no banco de dados?
    /// 2. Pertence ao usuário informado? (identityId)
    /// 3. Não foi revogado (logout)?
    /// 4. Não expirou?
    /// 
    /// Todas as 4 validações devem passar para retornar true.
    /// Se qualquer uma falhar, retorna false (não lança exceção).
    /// 
    /// QUERY SQL (conceitual):
    /// ───────────────────────
    /// SELECT * FROM RefreshTokens
    /// WHERE Token = @token
    ///   AND IdentityUserId = @identityId
    ///   AND Revogado = false
    ///   AND ExpiraEm > GETUTCDATE()
    /// 
    /// Se retorna 1 registro: token válido (retorna true)
    /// Se retorna 0 registros: token inválido (retorna false)
    /// 
    /// QUANDO USAR:
    /// ────────────
    /// 1. Endpoint /api/auth/refresh-token
    ///    - Cliente envia token para renovar
    ///    - Valida token antes de gerar novo access token
    /// 
    /// 2. Qualquer operação que exija token ainda ativo
    /// 
    /// EFEITO DO RETORNO:
    /// ──────────────────
    /// - true: Token é válido, pode usar para renovar
    /// - false: Token é inválido, cliente precisa fazer login de novo
    /// 
    /// POR QUE NÃO LANÇA EXCEÇÃO?
    /// ──────────────────────────
    /// Porque não encontrar o token não é erro técnico (é válido não encontrar)
    /// Deixa ao chamador decidir o que fazer (retornar 401, pedir login, etc)
    /// </summary>
    /// <param name="token">
    /// O refresh token a validar.
    /// 
    /// Tipo: string
    /// Formato: Base64 aleatório (gerado por GerarRefreshToken())
    /// 
    /// Exemplo: "PH1CrxuMWdIvT8m9lK2pqR3sTuVwXyZaBcDeFgHiJkL="
    /// 
    /// Este é o token que o cliente enviou
    /// Será consultado no banco para validar
    /// </param>
    /// <param name="identityId">
    /// ID do usuário que está tentando usar o token.
    /// 
    /// Tipo: string
    /// Origem: JWT claim "sub" (NameIdentifier)
    /// 
    /// Exemplo: "550e8400-e29b-41d4-a716-446655440000"
    /// 
    /// Função: Garantir que o token pertence ao usuário
    /// Segurança: Evita que Usuario A use refresh token de Usuario B
    /// </param>
    /// <returns>
    /// true se o token é válido e ativo.
    /// 
    /// Condições para retornar true:
    /// - Token existe no banco
    /// - Pertence ao usuário informado (identityId)
    /// - Não foi revogado (Revogado == false)
    /// - Não expirou (ExpiraEm > DateTime.UtcNow)
    /// 
    /// false se qualquer validação falhar.
    /// 
    /// IMPORTANTE: Este método nunca lança exceção.
    /// Apenas retorna false para permitir ao chamador decidir o que fazer.
    /// </returns>
    public async Task<bool> ValidarRefreshTokenAsync(string token, string identityId)
    {
        // Busca assincronamente no banco o primeiro refresh token que atenda:
        // 1. Token = token informado (string exata)
        // 2. IdentityUserId = identityId informado (pertence ao usuário)
        // FirstOrDefaultAsync: retorna o primeiro resultado ou null se não encontrar
        var refreshToken = await context.RefreshTokens
            .FirstOrDefaultAsync(rt =>
                rt.Token == token &&
                rt.IdentityUserId == identityId);

        // Se refresh token não existe no banco, retorna false
        // (não encontrou resultado = token inválido/nunca existiu)
        if (refreshToken == null)
            return false;

        // Valida se refresh token foi revogado
        // Revogado == true significa: foi marcado como inválido (logout ou token rotation)
        // Se foi revogado, retorna false (não pode usar)
        if (refreshToken.Revogado)
            return false;

        // Valida se refresh token expirou
        // ExpiraEm é DateTime no banco
        // DateTime.UtcNow é horário atual em UTC
        // Se ExpiraEm <= DateTime.UtcNow, significa: já passou a data de expiração
        if (refreshToken.ExpiraEm <= DateTime.UtcNow)
            return false;

        // Se passou todas as validações, token é válido
        // Retorna true (pode ser usado para renovar)
        return true;
    }

    /// <summary>
    /// Revoga um refresh token, marcando-o como inválido.
    /// 
    /// Revogação significa: marca o token como não mais utilizável
    /// 
    /// QUANDO USAR:
    /// ────────────
    /// 1. LOGOUT: usuário clica em "sair"
    ///    - Revoga o refresh token
    ///    - Mesmo que alguém roubar, não funciona mais
    /// 
    /// 2. TOKEN ROTATION: ao renovar token
    ///    - Valida refresh token antigo
    ///    - REVOGA refresh token antigo
    ///    - Emite novo refresh token
    ///    - Se alguém usar token antigo roubado, não funciona
    /// 
    /// 3. SEGURANÇA: suspeita de comprometimento
    ///    - Revoga todos os tokens do usuário
    ///    - Força o usuário fazer login de novo
    /// 
    /// 4. LIMPEZA: tokens expirados
    ///    - Limpeza periódica de tokens antigos (espaço no banco)
    /// 
    /// O QUE MUDA NO BANCO:
    /// ────────────────────
    /// ANTES:
    /// | Token | IdentityUserId | Revogado | RevogadoEm | ExpiraEm |
    /// | "ABC" | "user-123"     | false    | NULL       | 2025-04-20 |
    /// 
    /// DEPOIS:
    /// | Token | IdentityUserId | Revogado | RevogadoEm         | ExpiraEm |
    /// | "ABC" | "user-123"     | true     | 2025-04-13 15:30:45| 2025-04-20 |
    /// 
    /// Alterações:
    /// - Revogado: false → true
    /// - RevogadoEm: NULL → DateTime.UtcNow (horário atual)
    /// - ExpiraEm: sem mudança (deixa como está)
    /// 
    /// EFEITO IMEDIATO:
    /// ────────────────
    /// Após revogação, ValidarRefreshTokenAsync() retorna false:
    /// - if (refreshToken.Revogado) return false;
    /// 
    /// Token não pode mais ser usado para renovar
    /// Mesmo que não tenha expirado ainda
    /// 
    /// FLUXO DE LOGOUT COMPLETO:
    /// ──────────────────────────
    /// 1. Usuário clica em "Logout" na interface
    /// 2. Cliente envia: DELETE /api/auth/logout + { refreshToken }
    /// 3. Controller recebe request
    /// 4. Controller extrai identityId do JWT (User.FindFirst(ClaimTypes.NameIdentifier))
    /// 5. Controller chama: AutenticacaoService.LogoutAsync(refreshToken, identityId)
    /// 6. AutenticacaoService chama: TokenService.RevogarRefreshTokenAsync(refreshToken, identityId)
    /// 7. TokenService:
    ///    a. Busca token no banco
    ///    b. Marca Revogado = true
    ///    c. Seta RevogadoEm = DateTime.UtcNow
    ///    d. SaveChangesAsync()
    /// 8. Banco atualiza o registro
    /// 9. Token nunca mais funciona
    /// 10. Se alguém conseguiu o token: não consegue usar
    /// 11. ✅ Logout real e imediato!
    /// 
    /// COMPARAÇÃO: Logout com vs sem revogação
    /// ─────────────────────────────────────────
    /// 
    /// SEM revogação (apenas TTL):
    /// - Logout: cliente apaga token do localStorage
    /// - Realidade: se alguém roubou o token, pode usar por 7 dias
    /// - Não é logout de verdade (servidor não sabe)
    /// - Token continua válido no banco
    /// 
    /// COM revogação (nosso caso):
    /// - Logout: cliente apaga token + servidor revoga
    /// - Realidade: token é marcado como inválido no banco
    /// - Logout de verdade (servidor sabe e bloqueia)
    /// - Token não funciona mesmo que alguém tente usar
    /// - ✅ Mais seguro!
    /// </summary>
    /// <param name="token">
    /// O refresh token a revogar.
    /// 
    /// Tipo: string
    /// Formato: Base64 aleatório
    /// 
    /// Exemplo: "PH1CrxuMWdIvT8m9lK2pqR3sTuVwXyZaBcDeFgHiJkL="
    /// 
    /// Este é o token que o cliente estava usando
    /// Será marcado como revogado no banco
    /// </param>
    /// <param name="identityId">
    /// ID do usuário que está revogando o token.
    /// 
    /// Tipo: string
    /// 
    /// Exemplo: "550e8400-e29b-41d4-a716-446655440000"
    /// 
    /// Função: Garantir que o token pertence ao usuário
    /// Segurança: Evita que Usuario A revogue token de Usuario B
    /// </param>
    public async Task RevogarRefreshTokenAsync(string token, string identityId)
    {
        // Busca assincronamente no banco o refresh token a revogar
        // Filtra por:
        // 1. Token = token informado (qual token revogar)
        // 2. IdentityUserId = identityId informado (pertence ao usuário)
        // FirstOrDefaultAsync: retorna primeiro ou null
        var refreshToken = await context.RefreshTokens
            .FirstOrDefaultAsync(rt =>
                rt.Token == token &&
                rt.IdentityUserId == identityId);

        // Se token não encontrado no banco, apenas retorna sem fazer nada
        // Idempotência: revogar token que não existe = OK
        // Não lança exceção, é considerado sucesso (token está revogado, quer já existisse ou não)
        if (refreshToken == null)
            return;

        // Marca o refresh token como revogado
        // Revogado = true significa: token não funciona mais
        // ValidarRefreshTokenAsync() verificará essa flag antes de permitir uso
        refreshToken.Revogado = true;

        // Registra o momento da revogação
        // RevogadoEm = DateTime.UtcNow significa: quando foi revogado
        // Útil para auditoria (saber quando usuário fez logout ou teve token revogado)
        // RefreshToken entity tem RevogadoEm como DateTime? (nullable)
        refreshToken.RevogadoEm = DateTime.UtcNow;

        // Marca a entidade como modificada no Entity Framework
        // Não é necessário chamá-lo explicitamente na maioria dos casos
        // (EF Core rastreia automaticamente), mas é explícito e claro
        context.RefreshTokens.Update(refreshToken);

        // Persiste todas as alterações no banco de dados de forma assincronizada
        // SaveChangesAsync():
        // 1. Executa UPDATE RefreshTokens SET Revogado = true, RevogadoEm = ... WHERE ...
        // 2. Retorna numero de registros atualizados
        // 3. Assincronizado = não bloqueia thread
        await context.SaveChangesAsync();

        // Método concluído com sucesso
        // Token foi marcado como revogado no banco
        // Nunca mais será validado por ValidarRefreshTokenAsync()
    }
}
