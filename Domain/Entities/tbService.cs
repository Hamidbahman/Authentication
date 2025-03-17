using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Authentication.Domain.Enums;

namespace Authentication.Domain.Entities;

[Table("tbService")]
public class Service
{
    public ServiceTypes ServiceType {get;private set;}
    [Key]
    [StringLength(200)]
    public string? ServiceKey {get;private set;}
    [StringLength(200)]
    public string Rest {get;private set;}
    [ForeignKey("Actee")]
    public long ActeeId{get;private set;}

    public Actee? Actee {get;private set;}
    public Service (){}

    public Service(ServiceTypes serviceType, string serviceKey, string rest, long acteeId)
{
    ServiceType = serviceType;
    ServiceKey = serviceKey;
    Rest = rest;
    ActeeId = acteeId;
}

}
