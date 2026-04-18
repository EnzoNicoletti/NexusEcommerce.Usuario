using System.Net.Http.Json;
using System.Text.Json.Serialization;
using NexusEcommerce.Usuario.Application.DTOs;
using NexusEcommerce.Usuario.Application.Interfaces;

namespace NexusEcommerce.Usuario.Infrastructure.Services;

// O Primary Constructor (HttpClient httpClient) injeta automaticamente o client
// que configuramos no Program.cs
public class ViaCepService(HttpClient httpClient) : IConsultaCepService
{
    public async Task<EnderecoDto?> BuscarEnderecoPorCepAsync(string cep)
    {
        // 1. Limpeza de dados: remove o "-" se o front-end mandar "14800-000"
        var cepLimpo = new string(cep.Where(char.IsDigit).ToArray());

        if (cepLimpo.Length != 8) return null;

        // 2. Chamada Externa (I/O)
        var resposta = await httpClient
            .GetFromJsonAsync<ViaCepResponse>($"https://viacep.com.br/ws/{cepLimpo}/json/");

        // 3. Validação de retorno (O ViaCEP retorna erro=true se o CEP não existir)
        if (resposta is null || resposta.Erro) return null;

        // 4. Tradução (A Camada Anticorrupção em ação)
        return new EnderecoDto(
            resposta.Cep,
            resposta.Logradouro,
            resposta.Bairro,
            resposta.Localidade, // O ViaCEP chama cidade de "Localidade"
            resposta.Uf);
    }

    // DTO Interno: A Application não precisa (e nem deve) saber que isso existe.
    // Ele espelha exatamente o JSON do ViaCEP.
    private record ViaCepResponse(
        string Cep,
        string Logradouro,
        string Bairro,
        string Localidade,
        string Uf,
        [property: JsonPropertyName("erro")] bool Erro = false
    );
}