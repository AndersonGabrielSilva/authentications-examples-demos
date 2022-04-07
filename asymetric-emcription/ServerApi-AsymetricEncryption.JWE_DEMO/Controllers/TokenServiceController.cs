using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ServerApi_AsymetricEncryption.JWE_DEMO.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenServiceController : ControllerBase
    {
        private readonly ILogger<TokenServiceController> _logger;
        private readonly IJsonWebKeySetService jsonWebKeySetService;

        public TokenServiceController(ILogger<TokenServiceController> logger, IJsonWebKeySetService jsonWebKeySetService)
        {
            _logger = logger;
            this.jsonWebKeySetService = jsonWebKeySetService;
        }

        [HttpGet]
        public IActionResult Get(string jwe)
        {
            //Busca chave private corrente
            var key = jsonWebKeySetService.GetCurrentEncryptingCredentials();
            var teste = key.Enc;

            var chaveDescriptografia = new EncryptingCredentials(key: key.Key,
                                                                 alg: SecurityAlgorithms.RsaOAEP,
                                                                 enc: SecurityAlgorithms.Aes128CbcHmacSha256);

            //Valida Token
            var handler = new JsonWebTokenHandler();
            var result = handler.ValidateToken(jwe, new TokenValidationParameters()
            {
                ValidIssuer = "www.andersongabriel.dev",
                ValidAudience = "cartao-credito",
                RequireSignedTokens = false,
                TokenDecryptionKey = chaveDescriptografia.Key
            });

            if (result.IsValid)
                return Ok(result.Claims);

            return BadRequest("Token inválido");
        }
    }
}
