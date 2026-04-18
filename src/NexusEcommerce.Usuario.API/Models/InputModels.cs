using System.ComponentModel.DataAnnotations;

namespace NexusEcommerce.Usuario.API.Models;

public class RegistrarContaInputModel
{
    [Required(ErrorMessage = "E-mail é obrigatório")]
    [EmailAddress(ErrorMessage = "E-mail com formato inválido")]
    public required string Email { get; set; }

    [Required(ErrorMessage = "Senha é obrigatória")]
    [MinLength(8, ErrorMessage = "A senha deve ter no mínimo 8 caracteres")]
    public required string Senha { get; set; }
}

public class LoginInputModel
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required string Senha { get; set; }
}

public class CompletarPerfilInputModel
{
    [Required] public required string NomeCompleto { get; set; }
    [Required] public required string Cpf { get; set; }
    [Required] public required string Cep { get; set; }
    [Required] public required string NumeroEndereco { get; set; }
}
