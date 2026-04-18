using NexusEcommerce.Usuario.Domain.ValueObjects;
using NexusEcommerce.Usuario.Domain.Exceptions;

namespace NexusEcommerce.Usuario.Domain.Entities;

public class Cliente
{
    public Guid Id { get; private set; } = Guid.NewGuid();
    public string IdentityId { get; private set; } = string.Empty;
    public string NomeCompleto { get; private set; } = string.Empty;
    public Cpf Cpf { get; private set; } = null!;
    public string Email { get; private set; } = string.Empty;

    // Endereço agrupado (Propriedades opcionais até o onboarding etapa 2)
    public string? Cep { get; private set; }
    public string? Logradouro { get; private set; }
    public string? Bairro { get; private set; }
    public string? Cidade { get; private set; }
    public string? Estado { get; private set; }
    public string? NumeroEndereco { get; private set; }

    protected Cliente() { }

    public Cliente(string identityId, string nomeCompleto, string cpf, string email)
    {
        // Validação de negócio no domínio
        if (!email.Contains('@')) throw new DomainException("E-mail com formato inválido.");

        ArgumentNullException.ThrowIfNullOrWhiteSpace(identityId);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(nomeCompleto);

        IdentityId = identityId;
        NomeCompleto = nomeCompleto;
        Email = email.ToLower().Trim();
        Cpf = new Cpf(cpf);
    }

    public void AtribuirEndereco(
        string cep, string logradouro, string bairro,
        string cidade, string estado, string numero)
    {
        // Regra: Não se atribui endereço se o CEP for inválido
        if (string.IsNullOrWhiteSpace(cep) || cep.Length < 8)
            throw new DomainException("CEP inválido para atribuição de endereço.");

        Cep = cep;
        Logradouro = logradouro;
        Bairro = bairro;
        Cidade = cidade;
        Estado = estado;
        NumeroEndereco = numero;
    }
}