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

// Mapster
builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
builder.Services.AddScoped<IMapper, ServiceMapper>();

// 3. AUTENTICAÇÃO JWT
var jwtSection = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSection["Secret"]!);

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
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = jwtSection["Issuer"],
        ValidateAudience = true,
        ValidAudience = jwtSection["Audience"],
        ValidateLifetime = true,
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