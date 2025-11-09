using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using System.Security.Claims;

public class GenZrequirement : IAuthorizationRequirement
{
    public int MinYear { get; }

    public int MaxYear { get; }

    public GenZrequirement(int _minYear = 1997, int _maxYear = 2012)
    {
        MinYear = _minYear;
        MaxYear = _maxYear;
    }
}

public class GenZRequirementHandler : AuthorizationHandler<GenZrequirement>
{
    public GenZRequirementHandler()
    {

    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, GenZrequirement requirement)
    {
        var user = context.User;
        if(user.Identity.IsAuthenticated  ==false) 
        {
            context.Fail();
            return Task.CompletedTask; // 
        }
        var birthdate =Convert.ToInt64(user.Claims.FirstOrDefault(x => x.Type == ClaimTypes.DateOfBirth).Value);

        if (birthdate < requirement.MinYear || birthdate > requirement.MaxYear)
        {
            context.Fail();
            return Task.CompletedTask;
        }

        var scope = user.Claims.FirstOrDefault(x => x.Type == "scope").Value.ToString();
        if (scope.Contains("api.write"))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}