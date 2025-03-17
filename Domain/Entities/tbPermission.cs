using System;
using System.ComponentModel.DataAnnotations.Schema;
using Authentication.Domain.Enums;


namespace Authentication.Domain.Entities;

[Table("tbPermission")]
public class Permission : BaseEntity
{
    [ForeignKey("Actee")]
    public long ActeeId{get;private set;}
    public Actee Actee {get;private set;}
    [ForeignKey("Role")]
    public long RoleId{get;private set;}
    public Role Role {get;private set;}
    public StatusTypes Status {get;private set;}
    public int Granting {get;private set;}

    public Permission () {}

    public Permission(long acteeId, long roleId, StatusTypes status, int granting)
{
    ActeeId = acteeId;
    RoleId = roleId;
    Status = status;
    Granting = granting;
}


}
