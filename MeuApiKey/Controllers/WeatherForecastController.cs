using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Attributes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace MeuApiKey.Controllers
{
    [ApiController]
    [Route("weather")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [ApiKey]
        public IActionResult Get()
        {
            return Ok(new { message = "Você tem acesso!" });
        }
    }
}

/*
Testando a API
Agora vamos testar a API e se você utilizou um método GET como eu, 
basta chamar estes três endereços no seu browser.

https://localhost:5001/weather
https://localhost:5001/weather?api_key=12345
https://localhost:5001/weather?api_key=anderson_apiKey_IIugifrDYF/z0ey3NwCV/unWg==

Na primeira requisição você deve receber um erro 401, pois não informamos o ApiKey. 
Na segunda você deve receber um erro 403 pois o ApiKey é inválido, e por fim, 
devemos conseguir visualizar a mensagem "Você tem acesso!".
*/
