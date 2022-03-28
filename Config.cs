using AuthApi.Models;
using Duende.IdentityServer;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AuthApi;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.Profile()
        };
    public static IEnumerable<ApiResource> ApiResources =>
        new ApiResource[]
        {

        };
    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
            {
                new ApiScope(name:"CommerceApi",displayName:"Commerce_api"),
                new ApiScope(name:"Authenticated",displayName:"Authenticated User"),
                new ApiScope(name:"Admin",displayName:"Admin"),
                new ApiScope(IdentityServerConstants.LocalApi.ScopeName)
            };
    public class ExtensionGrantValidator : IResourceOwnerPasswordValidator
    {
        private SignInManager<ApplicationUser> _signIn;
        private UserManager<ApplicationUser> _userManager;
        public ExtensionGrantValidator(SignInManager<ApplicationUser> signIn, UserManager<ApplicationUser> userManager)
        {
            _signIn = signIn;
            _userManager = userManager;
        }
        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {

            var x = signInUser(context.UserName, context.Password).Result;


            if (x != null)
            {
                context.Result = new GrantValidationResult(
                    subject: x.Id.ToString(),
                    authenticationMethod: "custom"
                    );
            }
            else
            {
                // custom error message
                context.Result = new GrantValidationResult(
                    TokenRequestErrors.InvalidGrant,
                    "invalid credential");
            }

            return Task.CompletedTask;
        }
        public async Task<ApplicationUser> signInUser(string userName, string password)
        {
            var userLog = await _userManager.FindByNameAsync(userName);
            if (userLog != null)
            {
                SignInResult x = await _signIn.PasswordSignInAsync(userLog, password, false, false);
                if (!x.Succeeded || x.IsNotAllowed || x.IsLockedOut)
                {
                    userLog.AccessFailedCount++;
                    return null;
                }
                userLog.AccessFailedCount = 0;
                userLog.LastLogin = DateTime.Now;
                await _userManager.UpdateAsync(userLog);
                return userLog;
            }
            return null;
        }
    }
    public class CustomProfile : IProfileService
    {
        private UserManager<ApplicationUser> _userManager;
        public CustomProfile(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var SubjectId = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(SubjectId);
            
            var claims = new List<Claim>
            {
                new Claim("username", user.UserName),
                new Claim("email", user.Email),
                new Claim("IsConfirmed", user.IsConfirmed.ToString()),
                new Claim("IsDeleted", user.IsDeleted.ToString()),
                new Claim("PhoneNumber", user.PhoneNumber),
                new Claim("IsReported", user.IsReported.ToString()),
                new Claim("LockoutEnd", user.LockoutEnd.ToString()),
                new Claim("RegisteredTime", user.RegisteredTime.ToString()),
                new Claim("LastLogin", user.LastLogin.ToString()),
                new Claim("LockoutEnabled", user.LockoutEnabled.ToString()),
            };
            
            context.IssuedClaims = claims;
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            
            var SubjectId = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(SubjectId);
            context.IsActive = user != null;
        }
    }
}