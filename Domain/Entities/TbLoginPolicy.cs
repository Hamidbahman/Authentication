using System;
using System.ComponentModel.DataAnnotations.Schema;
using Authentication.Domain.Enums;

namespace Authentication.Domain.Entities
{
    public class LoginPolicy : BaseEntity
    {
        public LockTypes LockTypes { get; private set; }

        [ForeignKey("User")]
        public long UserId { get; private set; }
        public User User { get; private set; } 

        public DateTime LockStartDateTime { get; private set; }
        public DateTime LockEndDateTime { get; private set; }

        public LoginPolicy() {}

        public LoginPolicy(
            long id,
            DateTime createDate,
            DateTime modifyDate,
            DateTime? deleteDate,  // Make deleteDate nullable
            string? deleteUser,
            string? modifyUser,
            LockTypes lockTypes,
            long userId,
            DateTime lockStartDateTime,
            DateTime lockEndDateTime
        ) : base(id, createDate, modifyDate, deleteDate, deleteUser, modifyUser)
        {
            LockTypes = lockTypes;
            UserId = userId;
            LockStartDateTime = lockStartDateTime;
            LockEndDateTime = lockEndDateTime;
        }

        public void SetLockType(LockTypes lockType)
        {
            LockTypes = lockType;
        }
    }
}
