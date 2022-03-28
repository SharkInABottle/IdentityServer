using AuthApi.Models;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using static Duende.IdentityServer.IdentityServerConstants;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthApiFail.Controllers
{
    [Route("[controller]")]
    [ApiController]
    
    [Authorize(LocalApi.PolicyName)]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;
        public AuthController(IMapper mapper, UserManager<ApplicationUser> userManager)
        {
            _mapper = mapper;
            _userManager = userManager;
        }
        
        [HttpGet("{userName}")]
        public async Task<ActionResult<IQueryable<ApplicationUser>>> GetUser(string userName)
        {
            var x = await _userManager.FindByNameAsync(userName);
            
            if(x!=null)return Ok(x);
            else return NotFound(userName+"cannot be found");
        }
        [HttpPost]
        public async Task<ActionResult> SignUp(RegisterModel registerModel)
        {
            var user = _mapper.Map<RegisterModel, ApplicationUser>(registerModel);
            if(await _userManager.FindByNameAsync(user.UserName)!=null)return BadRequest("username already exists");
            user.IsConfirmed = false;
            user.IsDeleted = false;
            user.IsReported = false;
            user.RegisteredTime = DateTime.Now;
            user.ConfirmationCode = new Random().Next(100000,999999);
            var userCreateResult = await _userManager.CreateAsync(user, registerModel.Password);

            if (userCreateResult.Succeeded)
            {
                return Ok(user);
            }

            return BadRequest(userCreateResult.Errors.First().Description);
        }
        [Authorize(Policy ="IdentityScopeAdmin")]
        [HttpGet("")]
        public async Task<ActionResult> getUsers()
        {
            var x=await _userManager.Users.ToListAsync();
            return Ok(x);
        }
        [Authorize(Policy = "IdentityScope")]
        [HttpDelete("{Id}")]
        public async Task<ActionResult<IQueryable<ApplicationUser>>> DeleteUser(string id)
        {
            if (User.FindFirst("sub").Value != id) return BadRequest();
            var x= await _userManager.FindByIdAsync(id);
            if (x != null)
            {
                x.IsDeleted = true;
                var x1 = await _userManager.UpdateAsync(x);
                if (x1.Succeeded) return Ok();
                else return StatusCode(500, "Database error");
            }
            
            return NotFound();
        }
    }
}
