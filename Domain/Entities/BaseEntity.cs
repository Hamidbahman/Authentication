using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

public abstract class BaseEntity
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public virtual long Id { get; protected set; }  

    public virtual DateTime? CreateDate { get; private set; }
    public virtual DateTime? DeleteDate { get; private set; }
    
    [StringLength(50)]
    public virtual string? DeleteUser { get; private set; } = null;

    public virtual DateTime ModifyDate { get; private set; }

    [StringLength(50)]
    public virtual string? ModifyUser { get; private set; } = null;

    [Timestamp]
    public byte[]? RowVersion { get; private set; }

    protected BaseEntity(long id, DateTime createDate, DateTime modifyDate, DateTime? deleteDate = null, string? deleteUser = null, string? modifyUser = null)
    {
        Id = id;
        CreateDate = createDate;
        ModifyDate = modifyDate;
        DeleteDate = deleteDate;
        DeleteUser = deleteUser;
        ModifyUser = modifyUser;
    }

    protected BaseEntity() { }
}
