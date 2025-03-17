using System;
using System.ComponentModel.DataAnnotations.Schema;
using Authentication.Domain.Enums;

namespace Authentication.Domain.Entities
{
    [Table("tbUser")]
    public class User : BaseEntity
    {
        public string Uuid { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public string NationalCode { get; private set; }
        public string Email { get; private set; }
        public string Mobile { get; private set; }
        public string PrimaryKey { get; private set; }
        public string IpRange { get; private set; }
        public int LoginAttempt { get; private set; }
        public string Picture { get; private set; }
        public string PictureType { get; private set; }
        public string Scheduled { get; private set; }
        public StatusTypes Status { get; private set; }
        public bool TwoFactor { get; private set; }
        public string Description { get; private set; }

        // New UserName Property
        public string UserName { get; private set; }

        // One-to-one Relationships
        public UserRole UserRole { get; private set; }
        public UserProperty UserProperty { get; private set; }
        public LoginPolicy LoginPolicy { get; private set; }

        private User() { }

        public User(
            long id,
            DateTime createDate,
            DateTime modifyDate,
            DateTime? deleteDate,
            string? deleteUser,
            string? modifyUser,
            string uuid,
            string firstName,
            string mobile,
            string primaryKey,
            string ipRange,
            int loginAttempt,
            string picture,
            string pictureType,
            string scheduled,
            StatusTypes status,
            bool twoFactor,
            string lastName,
            string nationalCode,
            string email,
            string userName,  // New parameter for UserName
            string? description,
            UserProperty userProperty,
            UserRole userRole,
            LoginPolicy loginPolicy
        ) : base(id, createDate, modifyDate, deleteDate, deleteUser, modifyUser)
        {
            UserProperty = userProperty;
            UserRole = userRole;
            LoginPolicy = loginPolicy;
            Uuid = uuid;
            FirstName = firstName;
            LastName = lastName;
            NationalCode = nationalCode;
            Email = email;
            Mobile = mobile;
            Description = description;
            UserName = userName;  // Assigning UserName
            PrimaryKey = primaryKey;
            IpRange = ipRange;
            LoginAttempt = loginAttempt;
            Picture = picture;
            PictureType = pictureType;
            Scheduled = scheduled;
            Status = status;
            TwoFactor = twoFactor;
        }
                public void ResetLoginAttempt()
        {
            LoginAttempt = 0;
        }

        public void IncrementLoginAttempt()
        {
            LoginAttempt++;
        }
    }
}
