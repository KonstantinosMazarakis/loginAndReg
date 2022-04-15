using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace loginAndReg.Models
{
    public class LoginUser
    {

        [Required]
        [EmailAddress]
        public string Email {get;set;}
        
        [Required]
        [MinLength(8)]
        [DataType(DataType.Password)]
        public string Password {get;set;}

    }
}