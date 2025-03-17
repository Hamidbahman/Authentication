using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

[Table("tbMenu")]
public class Menu
{
    [Key]
    [StringLength(50)]
    public string MenuKey {get;private set;}
    public short Priority {get;private set;}
    [StringLength(50)]
    public string Icon {get;private set;}
    [ForeignKey("Actee")]
    public long ActeeId {get;private set;}
    public Actee Actee {get;private set;}

    public Menu() {}
    public Menu(string menuKey, short priority, string icon, long acteeId)
{
    MenuKey = menuKey;
    Priority = priority;
    Icon = icon;
    ActeeId = acteeId;
}

}