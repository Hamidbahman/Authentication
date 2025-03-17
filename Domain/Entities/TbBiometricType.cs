using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

    [Table("tbBiometricType")]
    public class BiometricType
    {
        [Key]
        [StringLength(25)]
        public string? Title { get;private set; }

        public ICollection<UserBiometric> UserBiometrics {get; private set;} = new List<UserBiometric>();
    
        public BiometricType (){}
        public BiometricType (
            string title
        ){

            Title = title;
        }
    }
