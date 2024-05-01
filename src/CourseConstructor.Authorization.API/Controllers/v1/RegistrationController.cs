using CourseConstructor.Authorization.API.Controllers.Base;
using Microsoft.AspNetCore.Mvc;

namespace CourseConstructor.Authorization.API.Controllers.v1;

[Route("register")]
[ApiController]
public class RegistrationController : BaseController
{
    public RegistrationController() : base()
    {
        
    }

    [HttpGet("in")]
    public async Task<IActionResult> Test()
    {
        return Ok(new {IsSuccess = false});
    }
    
}