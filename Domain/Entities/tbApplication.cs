using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

    [Table("tbApplication")]
    public class Application : BaseEntity
    {
        [Required]
        [StringLength(100)]
        public string Title { get; private set; }

        [StringLength(500)]
        public string RedirectUrls { get; private set; }

        [Required]
        [StringLength(50)]
        public string ClientId { get; private set; }

        [StringLength(200)]
        public string ClientScope { get; private set; }

        [StringLength(100)]
        public string ClientSecret { get; private set; }

        [StringLength(255)]
        public string AuthenticateGrantType { get; private set; }

        [StringLength(50)]
        public string IpRange { get; private set; }

        public bool IsAutoApprove { get; private set; }

        [StringLength(50)]
        public string Scheduled { get; private set; }

        public short Status { get; private set; }

        public bool LockEnabled { get; private set; }

        [StringLength(2000)]
        public string Description { get; private set; }

        public ConfigurationPassword ConfigurationPassword { get; private set; }
        public ConfigurationSession ConfigurationSession { get; private set; }
        public ICollection<ConfigurationLock> ConfigurationLocks { get; private set; } = new List<ConfigurationLock>();
        public ICollection<Role> Roles { get; private set; } = new List<Role>();
        public ICollection<ApplicationPackage> ApplicationPackages { get; private set; } = new List<ApplicationPackage>();

        public Application() { }

        public Application(
            ConfigurationPassword configurationPassword,
            List<ConfigurationLock> configurationLocks,
            ConfigurationSession configurationSession,
            List<ApplicationPackage> applicationPackages,
            IEnumerable<Role> roles,
            long id,
            string title,
            string clientId,
            string? redirectUrls = null,
            string? clientScope = null,
            string? clientSecret = null,
            string? authenticateGrantType = null,
            string? ipRange = null,
            bool isAutoApprove = false,
            string? scheduled = null,
            short status = 0,
            bool lockEnabled = true,
            string? description = null,
            DateTime? createDate = null,
            DateTime? modifyDate = null,
            DateTime? deleteDate = null,
            string? deleteUser = null,
            string? modifyUser = null
        ) : base(id, createDate ?? new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), 
                modifyDate ?? new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), 
                deleteDate, deleteUser, modifyUser)
        {
            Title = title ?? throw new ArgumentNullException(nameof(title));
            ClientId = clientId ?? throw new ArgumentNullException(nameof(clientId));
            RedirectUrls = redirectUrls;
            ClientScope = clientScope;
            ClientSecret = clientSecret;
            AuthenticateGrantType = authenticateGrantType;
            IpRange = ipRange;
            IsAutoApprove = isAutoApprove;
            Scheduled = scheduled;
            Status = status;
            LockEnabled = lockEnabled;
            Description = description;
            ApplicationPackages = applicationPackages?.ToList() ?? new List<ApplicationPackage>();
            ConfigurationPassword = configurationPassword;
            ConfigurationLocks = configurationLocks?.ToList() ?? new List<ConfigurationLock>(); 
            ConfigurationSession = configurationSession;
            Roles = roles?.ToList() ?? new List<Role>();
        }
    }

