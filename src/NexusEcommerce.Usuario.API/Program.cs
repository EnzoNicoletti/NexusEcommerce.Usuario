using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using NexusEcommerce.Usuario.Application.Interfaces;
using NexusEcommerce.Usuario.Infrastructure.Data;
using NexusEcommerce.Usuario.Infrastructure.Services;
using Scalar.AspNetCore;
using Mapster;
using MapsterMapper;
using NexusEcommerce.Usuario.Domain.Entities;
using NexusEcommerce.Usuario.Application.DTOs;

var builder = WebApplication.CreateBuilder(args);

// 1. BANCO DE DADOS E IDENTITY
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityCore<IdentityUser>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// 2. INJEÇÃO DE DEPENDÊNCIA (DI)
builder.Services.AddHttpClient<IConsultaCepService, ViaCepService>();
builder.Services.AddScoped<IClienteService, ClienteService>();

// TokenService: Geração e validação de JWT + Refresh Tokens
builder.Services.AddScoped<ITokenService, TokenService>();

// ✨ AutenticacaoService (PASSO 13)
// Orquestra todas as operações de autenticação: login, refresh, logout, listagem, roles
// Dependências:
// - UserManager<IdentityUser> → Gerencia usuários (Identity)
// - ApplicationDbContext → Acesso ao banco (RefreshTokens)
// - IClienteService → Busca dados do cliente
// - ITokenService → Gera/valida tokens
builder.Services.AddScoped<IAutenticacaoService, AutenticacaoService>();

// Mapster
builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
builder.Services.AddScoped<IMapper, ServiceMapper>();

// 3. AUTENTICAÇÃO JWT
// Lê as configurações do appsettings.json
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"]
    ?? throw new InvalidOperationException("JwtSettings:SecretKey não configurado em appsettings.json");
var issuer = jwtSettings["Issuer"] ?? "NexusEcommerce";
var audience = jwtSettings["Audience"] ?? "NexusEcommerceUsers";

// Converte a chave secreta (string) para bytes (SymmetricSecurityKey exige bytes)
var keyBytes = Encoding.UTF8.GetBytes(secretKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        // IssuerSigningKey: chave para verificar a assinatura do JWT
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),

        ValidateIssuer = true,
        ValidIssuer = issuer,

        ValidateAudience = true,
        ValidAudience = audience,

        ValidateLifetime = true,
        // ClockSkew: tolerância de tempo (0 = sem tolerância, token expirado = rejeita)
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();

// 4. MAPSTER CONFIG (Mapeamento de VO para DTO)
TypeAdapterConfig<Cliente, ClienteResponseDto>
    .NewConfig()
    .Map(dest => dest.CpfFormatado, src => src.Cpf.ObterFormatado());

// 5. OPENAPI + SCALAR
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, ct) =>
    {
        document.Info.Title = "Nexus Ecommerce — Microsserviço de Usuários";

        document.Components ??= new OpenApiComponents();

        // Instanciamos a classe concreta (Dictionary) em vez de deixar o compilador adivinhar a interface
        document.Components.SecuritySchemes = new Dictionary<string, IOpenApiSecurityScheme>
        {
            ["Bearer"] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = "Cole o token JWT gerado no login"
            }
        };

        return Task.CompletedTask;
    });
});

var app = builder.Build();

// 6. PIPELINE DE MIDDLEWARE
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(opt => opt
        .WithTitle("Nexus — API Docs")
        .WithTheme(ScalarTheme.DeepSpace)
        .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient));
}

// A ORDEM É CRÍTICA: Autenticação SEMPRE vem antes de Autorização
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();