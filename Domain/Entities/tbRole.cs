using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Authentication.Domain.Enums;

namespace Authentication.Domain.Entities;
public class Role : BaseEntity
{
    [StringLength(40)]
    public string Uuid { get; private set; }

    public AuthorityTypes Authority { get; private set; }

    [StringLength(200)]
    public string? Title { get; private set; }

    [StringLength(2000)]
    public string? Description { get; private set; }

    [StringLength(30)]
    public string? IpRange { get; private set; }

    [StringLength(400)]
    public string Scheduled { get; private set; }

    public StatusTypes Status { get; private set; }

    [ForeignKey("ApplicationId")]
    public long ApplicationId { get; private set; }

    public Application? Application { get; private set; }

    public bool IsAdmin { get; private set; } = false;

    public ICollection<UserRole> UserRoles { get; private set; } = new List<UserRole>();

    public ICollection<Permission> Permissions { get; private set; } = new List<Permission>();

    public Role() { }

    public Role(
        ICollection<Permission> permissions,
        ICollection<UserRole> userRoles,
        long id,
        string uuid,
        AuthorityTypes authority,
        string title,
        string description,
        string ipRange,
        string scheduled,
        StatusTypes status,
        long applicationId,
        bool isAdmin)
    {
        Permissions = permissions ?? new List<Permission>();
        UserRoles = userRoles ?? new List<UserRole>();
        Id = id;
        Uuid = uuid;
        Authority = authority;
        Title = title;
        Description = description;
        IpRange = ipRange;
        Scheduled = scheduled;
        Status = status;
        ApplicationId = applicationId;
        IsAdmin = isAdmin;
    }
}
