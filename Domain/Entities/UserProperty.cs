using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

[Table("tbUserProperty")]
public class UserProperty
{
    [Key]
    public long UserId { get; private set; }
    
    public User? User { get; private set; } = null!;

    [Required]
    [StringLength(255)]
    public string Password { get; private set; } = null!;

    public long ConfigurationPasswordId { get; private set; }

    [ForeignKey(nameof(ConfigurationPasswordId))]
    public ConfigurationPassword ConfigurationPassword { get; private set; } = null!;

    public UserProperty() { }

    public UserProperty(long userId, string password, long configurationPasswordId)
    
    {
        UserId = userId;
        Password = password;
        ConfigurationPasswordId = configurationPasswordId;
    }
    public void UpdatePassword(string newPassword)
    {
        Password = newPassword;
    }
}