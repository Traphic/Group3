using System.ComponentModel.DataAnnotations;

namespace Blog.BlazorServer.ViewModels.Auth
{
    public class RegisterViewModel
    {
        [Display(Name = "Username")]
        [Required(ErrorMessage = "Username is required")]
        [StringLength(15, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 2)]
        public string Username { get; set; }

        [Display(Name = "Email")]
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Required(ErrorMessage = "Confirm password is required")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
