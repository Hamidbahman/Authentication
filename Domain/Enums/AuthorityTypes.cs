using System.ComponentModel;

namespace Authentication.Domain.Enums;

public enum AuthorityTypes
{
    [Description("Admin")]
    Admin = 1,
    [Description("User")]
    User = 2,
    [Description("Guest")]
    Guest = 3
}
