using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[Route("[controller]")]
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _configuration;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpPost]
    public async Task<IActionResult> Register(string username, string password)
    {
        var user = new ApplicationUser { UserName = username };
        var result = await _userManager.CreateAsync(user, password);
        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            return Ok(new { Username = user.UserName });
        }
        return BadRequest(result.Errors);
    }

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        var result = await _signInManager.PasswordSignInAsync(username, password, isPersistent: false, lockoutOnFailure: false);
        if (result.Succeeded)
        {
            var user = await _userManager.FindByNameAsync(username);
            var token = GenerateJwtToken(user);
            return Ok(new { Token = token });
        }

        return Unauthorized();
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtKey"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            // Add additional claims as needed
        };

        var token = new JwtSecurityToken(
            issuer: null,
            audience: null,
            claims: claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    [Authorize]
    [HttpGet]
    public string GetName()
    {
        return "Ahmad hasan";
    }
}
