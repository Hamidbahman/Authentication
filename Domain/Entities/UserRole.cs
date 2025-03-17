using System;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Authentication.Domain.Entities;

[Table("tbUserRole")]
public class UserRole : BaseEntity
{
    public long UserId { get; private set; }
    [JsonIgnore]
    public User User { get; private set; }

    public long RoleId { get; private set; }
    [JsonIgnore]
    public Role Role { get; private set; }

    public bool IsDefault { get; private set; }

    private UserRole(){}
    public UserRole(
        long id,
        DateTime createDate,
        DateTime modifyDate,
        DateTime? deleteDate,
        string? deleteUser,
        string? modifyUser,
        long userId,
        long roleId,
        bool isDefault
    ) : base(id, createDate, modifyDate, deleteDate, deleteUser, modifyUser)
    {
        UserId = userId;
        RoleId = roleId;
        IsDefault = isDefault;
    }
}
