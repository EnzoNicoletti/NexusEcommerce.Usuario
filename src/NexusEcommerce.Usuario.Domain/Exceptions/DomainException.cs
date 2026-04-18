namespace NexusEcommerce.Usuario.Domain.Exceptions;

/// <summary>
/// Exceção de domínio: representa violação de regra de negócio.
/// Permite que a API trate erros de domínio (400) separado de erros
/// de infraestrutura (500) no middleware de exceções.
/// </summary>
public class DomainException : Exception
{
    public DomainException(string message) : base(message) { }
}