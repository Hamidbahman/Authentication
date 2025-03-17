using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

[Table("tbUserBiometric")]
public class UserBiometric : BaseEntity
{
    [ForeignKey("BiometricType")]
    public string BiometricTitle {get;private set;}
    public BiometricType BiometricType {get; private set;}
    [ForeignKey("User")]
    public long UserId {get;private set;}
    public User? User {get;private set;}

    public UserBiometric() {}

    public UserBiometric(
        string biometricTitle,
        long userId,
        long id
    ){
        BiometricTitle = biometricTitle;
        UserId = userId;
        Id = id;
    }
}
