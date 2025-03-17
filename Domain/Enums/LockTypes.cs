namespace Authentication.Domain.Enums;

public enum LockTypes : short
{
    None = 5,
    TemporaryLock = 1,
    PermanentLock = 2,
    ExpiringLock = 3,
    ConditionalLock = 4,

}
