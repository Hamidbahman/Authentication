using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

[Table("tbApplicationPackage")]
public class ApplicationPackage : BaseEntity
{
    [StringLength(100)]
    public string Title {get;private set;}
    [ForeignKey("Application")]
    public long ApplicationId {get;private set;}
    public Application Application {get;private set;}

    public ApplicationPackage(){}
    public ApplicationPackage(
        long id,
        string title,
        long applicationId
    ){
        Id = id;
        Title = title;
        ApplicationId = applicationId;
    }
}
