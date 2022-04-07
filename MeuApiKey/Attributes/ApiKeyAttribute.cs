
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Attributes
{

    /*Desta forma, poderemos utilizar uma notação [ApiKey] tanto na classe (Controller) 
      quanto em um método (Action).*/
    [AttributeUsage(validOn: AttributeTargets.Class | AttributeTargets.Method)]
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {

        #region Atributos
        /*
            Aqui está o ponto chave deste artigo, o ApiKey que definimos acima é a chave de 
            acesso a toda API. Quem utilizar esta chave, "está no comando".
            
            A ideia aqui é ter uma chave (Ou várias) para saber se a requisição é valida. 
            Posteriormente você pode melhorar isto, inclusive lendo as chaves 
            do banco de dados por exemplo.
        */
        private const string ApiKeyName = "api_key";
        private const string ApiKey = "anderson_apiKey_IIugifrDYF/z0ey3NwCV/unWg==";
        #endregion

        /*
        Ao herdar da classe Attribute e IAsyncActionFilter somos obrigados a implementar 
        o método OnActionExecutionAsync, onde poderemos inspecionar a requisição atual.
        
        Neste caso, vamos inspecionar o context.HttpContext.Request que possui tanto a 
        propriedade Headers quanto Query, se referindo aos cabeçalhos e a URL da requisição respectivamente.
        
        Logo, se queremos obter um valor da URL, utilizamos context.HttpContext.Request.Query, enquanto para 
        obter um valor dos cabeçalhos utilizamos context.HttpContext.Request.Headers.

        A única coisa que precisamos nos atentar é que podemos ter mais de um valor com o mesmo nome ou mesmo nenhum valor.
        Desta forma é recomendado utilizar a extensão TryGetValue para não ter exceções na execução do código
        */
        public async Task OnActionExecutionAsync(
            ActionExecutingContext context,
            ActionExecutionDelegate next)
        {
            #region Verifirica se possui alguma chave
            if (!context.HttpContext.Request.Query.TryGetValue(ApiKeyName, out var extractedApiKey))
            {
                // Não encontrou
                context.Result = new ContentResult()
                {
                    //401 - Unauthorized
                    StatusCode = 401,
                    Content = "ApiKey não encontrada"
                };
                return;
            }
            #endregion

            #region Verifica se a chave é valida
            if (!ApiKey.Equals(extractedApiKey))
            {
                //Não é valida
                context.Result = new ContentResult()
                {
                    //403 - Forbidden
                    StatusCode = 403,
                    Content = "Acesso não autorizado"
                };
                return;
            }
            #endregion

            await next();
        }
    }
}