using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

    [Table("tbConfigurationPassword")]
    public class ConfigurationPassword : BaseEntity
    {
        public bool IsComplex { get; private set; } = false;
        public bool MustBeChangedInFirstLogin { get; private set; } = false;
        public bool MustContainChar { get; private set; } = false;
        public bool MustContainUpperCase { get; private set; } = false;
        public bool IsPolicyNeeded { get; private set; } = false;
        public short MinPassLength { get; private set; }
        public short MaxPassLength { get; private set; }
        public short NumericPassNotEqual { get; private set; }
        public bool WillPassExpire { get; private set; } = false;
        public short ExpireDaysAmount { get; private set; }
        public bool RedirectToCustomUrlAfterChangePass { get; private set; } = false;
        [StringLength(40)]
        public string UrlAfterChangePass { get; private set; }
        [ForeignKey("Application")]
        public long ApplicationId { get; private set; }
        public Application Application { get; private set; }
        public bool TwoFactorEnabled { get; private set; } = false;

        public ICollection<UserProperty> UserProperties { get; private set; }

        public ConfigurationPassword() { }

        public ConfigurationPassword(
            ICollection<UserProperty> userProperties,
            long id,
            bool isComplex,
            bool mustBeChangedInFirstLogin,
            bool mustContainChar,
            bool mustContainUpperCase,
            bool isPolicyNeeded,
            short minPassLength,
            short maxPassLength,
            short numericPassNotEqual,
            bool willPassExpire,
            short expireDaysAmount,
            bool redirectToCustomUrlAfterChangePass,
            string urlAfterChangePass,
            long applicationId,
            bool twoFactorEnabled)
        {
            Id = id;
            IsComplex = isComplex;
            MustBeChangedInFirstLogin = mustBeChangedInFirstLogin;
            MustContainChar = mustContainChar;
            MustContainUpperCase = mustContainUpperCase;
            IsPolicyNeeded = isPolicyNeeded;
            MinPassLength = minPassLength;
            MaxPassLength = maxPassLength;
            NumericPassNotEqual = numericPassNotEqual;
            WillPassExpire = willPassExpire;
            ExpireDaysAmount = expireDaysAmount;
            RedirectToCustomUrlAfterChangePass = redirectToCustomUrlAfterChangePass;
            UrlAfterChangePass = urlAfterChangePass;
            ApplicationId = applicationId;
            TwoFactorEnabled = twoFactorEnabled;

            // Set the relationship
            UserProperties = userProperties?? new List<UserProperty>();
        }
    }

