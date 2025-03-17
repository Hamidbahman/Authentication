
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

[Table("tbVerificationCode")]
public class VerificationCode : BaseEntity
{
    [StringLength(50)]
    public string ClientId {get;private set;}
    [StringLength(50)]
    public string UserName {get;private set;}
    [StringLength(13)]
    public string Mobile {get;private set;}
    [StringLength(50)]
    public int VerifyCode {get;private set;}
    [StringLength(255)]
    public string Description {get;private set;}
    public DateTime TicketExpireDate {get;private set;}
    public bool IsVerified {get;private set;} = false;


    public VerificationCode(){}
  public VerificationCode(
    string clientId,
    string userName,
    string mobile,
    int verifyCode,
    string description,
    DateTime ticketExpireDate,
    bool isVerified = false
)
{
    ClientId = clientId;
    UserName = userName;
    Mobile = mobile;
    VerifyCode = verifyCode;
    Description = description;
    TicketExpireDate = ticketExpireDate;
    IsVerified = isVerified;
}
}