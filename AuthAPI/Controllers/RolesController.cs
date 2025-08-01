// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Mvc;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using API.Dtos;
using API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthAPI.Model;



namespace AuthAPI.Controllers
{
    public class RolesController
    {
        // Creamos los nuevos endpoints para manejar los roles de los usuarios:

        [Authorize(Roles = "Admin")]
        [ApiController]
        [Route("api/[controller]")]
        public class RolesController:ControllerBase
        {

            // 
            private readonly RoleManager<IdentityRole> _roleManager;
            private readonly UserManager<AppUser> _userManager;

            // 
            public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager)
            {
                _roleManager = roleManager;
                _userManager = userManager;
            }


            // Creamos un nuevo rol dentro de la base de datos:
            [HttpPost]
            public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
            {
                if (string.IsNullOrEmpty(createRoleDto.RoleName))
                {
                    return BadRequest("Role name is required");
                }

                var roleExist = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);

                if (roleExist)
                {
                    return BadRequest("Role already exist");
                }

                var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));

                if (roleResult.Succeeded)
                {
                    return Ok(new { message = "Role Created successfully" });
                }

                return BadRequest("Role creation failed.");

            }




            // Endpoint para obtener todos los roles
        }


    }
}
