using Microsoft.AspNetCore.Identity;

namespace AuthAPI.Model
{
// Heradmos el modelo de Identity
    public class AppUser : IdentityUser
    {
        // 
        public string? FullName { get; set; }
    }
}
