namespace NexusEcommerce.Usuario.Application.DTOs;

// Response: O que devolvemos para o mundo externo
public record ClienteResponseDto(
    Guid Id,
    string NomeCompleto,
    string Email,
    string CpfFormatado
);

// Request: O que precisamos para completar o perfil
public record CompletarPerfilDto(
    string NomeCompleto,
    string Cpf,
    string Cep,
    string NumeroEndereco
);

// Contrato de Endereço (Vindo de serviços externos como ViaCEP)
public record EnderecoDto(
    string Cep,
    string Logradouro,
    string Bairro,
    string Localidade,
    string Uf
);