using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Security.Jwt.AspNetCore;
using NetDevPack.Security.Jwt.Core;
using NetDevPack.Security.Jwt.Core.Interfaces;
using RefreshToken;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

var builder = WebApplication.CreateBuilder(args);

//Use MemoryDataBase
builder.Services.AddDbContext<RefreshTokenContext>(options => options.UseInMemoryDatabase("RT"));

//Adiciona Define o Banco de Dados
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<RefreshTokenContext>().AddDefaultTokenProviders();

//Adiciona a Authentication via JWT 
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        //Configura validaçoes somente os Issuers e Audiaences adicionados aqui serão aceitos
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = "https://refreshtoken.test",
        ValidAudience = "RefreshToken.API"
    };
});

//Configura os servicos de Authentication
builder.Services.AddAuthorization();
builder.Services.AddMemoryCache();
builder.Services.AddJwksManager().PersistKeysInMemory().UseJwtValidation();

//Sinalizador que indica se as PII são ou não mostradas nos logs. Falso por padrão.
IdentityModelEventSource.ShowPII = true;

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Refresh Token Sample",
        Description = "Anotaçoes referente a demo Reflesh Token do Bruno Brito",
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    //Configura mensagem que irá ser exibida na modal de authorizations do SwaggerGen
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

//Constroi aplicação
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


// Gerando o AccessToken - nada mais é do que um Token Jwt Comum
static async Task<string> GenerateAccessToken(UserManager<IdentityUser> userManager, IJwtService jwtService, string? email)
{
    var user = await userManager.FindByEmailAsync(email);
    var userRoles = await userManager.GetRolesAsync(user);
    var identityClaims = new ClaimsIdentity();
    identityClaims.AddClaims(await userManager.GetClaimsAsync(user));
    identityClaims.AddClaims(userRoles.Select(s => new Claim("role", s)));

    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Email, user.Email));
    identityClaims.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

    var handler = new JwtSecurityTokenHandler();

    var securityToken = handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "https://refreshtoken.test",//normalmente aqui eu informa a url da minha aplicacao
        Audience = "RefreshToken.API",

        //Configuração para utilizar criptografia Asymetrica - [Poderia ser a criptografia simetrica, por exemplo apenas uma Key]
        SigningCredentials = await jwtService.GetCurrentSigningCredentials(),
        Subject = identityClaims,
        NotBefore = DateTime.UtcNow,
        Expires = DateTime.UtcNow.AddMinutes(60),
        IssuedAt = DateTime.UtcNow,
        
        // É uma boa pratica concatenar o "at" ao tipo de Token quando for AcessToken. [at = acessToken] - conceito utilizado no OAuth2
        //Outra boa pratica é sempre o acessToken não possuir um tempo longo de validade, o recomendado é de 1 hora;
        TokenType = "at+jwt"  
    });

    var encodedJwt = handler.WriteToken(securityToken);
    return encodedJwt;
}

/*O Reflesh token pode ser uma informação qualquer, ele pode ser um Guid, um ID, uma Jwt. Desde que esta qualquer coisa possua uma ligação com o usuario.
  Nesta demo resolvemos utilizar um token JWT, na qual éstamos adicionando o email do usuario para criar está ligação com o usuario.*/

// Gerando o RefleshToken - nada mais é do que um Token Jwt Comum
static async Task<string> GenerateRefreshToken(UserManager<IdentityUser> userManager, IJwtService jwtService, string? email)
{
    //var user = userManager.FindByEmailAsync(email);
    //var claims = new List<Claim> { new Claim(JwtRegisteredClaimNames.Sub, user.Id) };

    var claims = new List<Claim> { new Claim(JwtRegisteredClaimNames.Email, email) };

    // Necessário converver para IdentityClaims
    var identityClaims = new ClaimsIdentity();
    identityClaims.AddClaims(claims);

    var handler = new JwtSecurityTokenHandler();

    var securityToken = handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "https://refreshtoken.test",//normalmente aqui eu informa a url da minha aplicacao
        Audience = "RefreshToken.API",
        SigningCredentials = await jwtService.GetCurrentSigningCredentials(),
        Subject = identityClaims,
        NotBefore = DateTime.Now,
        Expires = DateTime.Now.AddDays(30),

        // É uma boa pratica concatenar o "rt" ao tipo de Token quando for refleshToken. [rt = RefleshToken] - conceito utilizado no OAuth2
        TokenType = "rt+jwt"
    });

    var encodedJwt = handler.WriteToken(securityToken);
    return encodedJwt;
}

app.MapPost("/accounts", [AllowAnonymous] async (
        UserManager<IdentityUser> userManager,
        UserRegister registerUser) =>
    {
        if (!MiniValidator.TryValidate(registerUser, out var errors))
            return Results.ValidationProblem(errors);

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        //Criando novo usuario com aspnet identity
        var result = await userManager.CreateAsync(user, registerUser.Password);

        if (!result.Succeeded)
            return Results.BadRequest(result.Errors);

        return Results.Ok();

    }).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("New user")
    .WithTags("user");


app.MapPost("/sign-in", [AllowAnonymous] async (
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IJwtService jwtService,
        UserLogin login) =>
    {
        if (!MiniValidator.TryValidate(login, out var errors))
            return Results.ValidationProblem(errors);

        //Verifica senha do usuario
        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, false, true);
                
        //Verifica se o usuário que está tentando entrar está bloqueado.
        if (result.IsLockedOut)
            return Results.BadRequest("Account blocked");

        //Caso a senha não esteja correta
        if (!result.Succeeded)
            return Results.BadRequest("Invalid username or password");

        //Gera o AcessToken
        var at = await GenerateAccessToken(userManager, jwtService, login.Email);

        //Gera o RefleshToken
        var rt = await GenerateRefreshToken(userManager, jwtService, login.Email);

        return Results.Ok(new UserLoginResponse(at, rt));

    }).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("Sign-in")
    .WithTags("user");


app.MapPost("/refresh-token", [AllowAnonymous] async (
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IJwtService jwtService,
        [FromForm] Token token) =>
    {
        if (!MiniValidator.TryValidate(token, out var errors))
            return Results.ValidationProblem(errors);

        var handler = new JsonWebTokenHandler();

        //Valida o reflesh Token
        var result = handler.ValidateToken(token.RefreshToken, new TokenValidationParameters()
        {
            ValidIssuer = "https://refreshtoken.test",//normalmente aqui eu informa a url da minha aplicacao
            ValidAudience = "RefreshToken.API",
            RequireSignedTokens = false,
            IssuerSigningKey = await jwtService.GetCurrentSecurityKey(),
        });

        //Caso o Token não esteja Valido é uma boa pratica apenas informas que o Token não seja para não dar mais detalhes sobre o que está invalido
        if (!result.IsValid)
            return Results.BadRequest("Expired token");

        var user = await userManager.FindByEmailAsync(result.Claims[JwtRegisteredClaimNames.Email].ToString());

        //Verifica se o Bloqueio está ativo para este usuario
        if(user.LockoutEnabled)
            if (user.LockoutEnd < DateTime.Now) // Verifica se o prazo de bloqueio já passou
                return Results.BadRequest("User blocked");

        //Exemplo de como buscar Clains do usuario 
        var claims = await userManager.GetClaimsAsync(user);
        if (claims.Any(c => c.Type == "TenhoQueRelogar" && c.Value == "true"))
            return Results.BadRequest("User must login again");


        var at = await GenerateAccessToken(userManager, jwtService, result.Claims[JwtRegisteredClaimNames.Email].ToString());
        var rt = await GenerateRefreshToken(userManager, jwtService, result.Claims[JwtRegisteredClaimNames.Email].ToString());
        return Results.Ok(new UserLoginResponse(at, rt));


    }).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("Refresh Token")
    .WithTags("user");

app.MapGet("/protected-endpoint", [Authorize] (IHttpContextAccessor context) =>
{
    return Results.Ok(context.HttpContext?.User.Claims.Select(s => new { s.Type, s.Value }));
});

app.Run();
