using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Authentication.Domain.Enums;

namespace Authentication.Domain.Entities;

[Table("tbActee")]
public class Actee : BaseEntity
{
    [StringLength(40)]
    public string Uuid { get; private set; }
    public ActeeTypes ActeeType { get; private set; }

    [StringLength(50)]
    public string Title { get; private set; }
    [StringLength(2000)]
    public string Description { get; private set; }
    public StatusTypes Status { get; private set; }
    
    [ForeignKey("ApplicationPackageId")]
    
    public ApplicationPackage ApplicationPackage { get; set; }
    
    public long ApplicationPackageId { get; private set; }

    public Actee (){}

    public Actee(
    string uuid,
    ActeeTypes acteeType,
    string title,
    string description,
    StatusTypes status,
    long applicationPackageId
)
{
    Uuid = uuid;
    ActeeType = acteeType;
    Title = title;
    Description = description;
    Status = status;
    ApplicationPackageId = applicationPackageId;
}

}