using NexusEcommerce.Usuario.Domain.Exceptions;

namespace NexusEcommerce.Usuario.Domain.ValueObjects;

public record Cpf
{
    public string Numero { get; init; }

    public Cpf(string numero)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(numero);

        // Otimização: Limpeza sem LINQ para evitar alocações extras
        Span<char> cleaned = stackalloc char[11];
        int count = 0;
        foreach (char c in numero)
        {
            if (char.IsDigit(c) && count < 11)
                cleaned[count++] = c;
        }

        if (count != 11 || !IsValid(cleaned))
            throw new DomainException("O CPF informado é inválido.");

        Numero = cleaned.ToString();
    }

    private static bool IsValid(ReadOnlySpan<char> cpf)
    {
        // Verifica se todos os dígitos são iguais
        bool allEqual = true;
        for (int i = 1; i < 11; i++)
            if (cpf[i] != cpf[0]) allEqual = false;

        if (allEqual) return false;

        // Cálculos de dígitos (Mantendo sua lógica correta, mas com Span)
        int[] multiplicador1 = { 10, 9, 8, 7, 6, 5, 4, 3, 2 };
        int[] multiplicador2 = { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2 };

        int soma = 0;
        for (int i = 0; i < 9; i++)
            soma += (cpf[i] - '0') * multiplicador1[i];

        int resto = soma % 11;
        int d1 = resto < 2 ? 0 : 11 - resto;
        if (cpf[9] - '0' != d1) return false;

        soma = 0;
        for (int i = 0; i < 10; i++)
            soma += (cpf[i] - '0') * multiplicador2[i];

        resto = soma % 11;
        int d2 = resto < 2 ? 0 : 11 - resto;
        return cpf[10] - '0' == d2;
    }

    public string ObterFormatado() => $"{Numero[..3]}.{Numero[3..6]}.{Numero[6..9]}-{Numero[9..]}";

    public override string ToString() => Numero; // Melhor retornar o limpo no ToString para logs/db
}