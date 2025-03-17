using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

[Table("tbMask")]
public class Mask
{
    [Key]
    public int MaskId { get; private set; }

    [ForeignKey("Permission")]
    public long PermissionId { get; private set; }
    public Permission Permission { get; private set; }

    public Mask() {}

    public Mask(long permissionId)
    {
        PermissionId = permissionId;
    }
}
