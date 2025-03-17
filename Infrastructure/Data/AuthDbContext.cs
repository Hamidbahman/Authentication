using Authentication.Domain.Entities;
using Authentication.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;

namespace Authenitcation.Infrastructure.Data
{
    public class AutheDbContext : DbContext
    {
        public AutheDbContext(DbContextOptions options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<Application> Applications { get; set; }
        public DbSet<ConfigurationPassword> ConfigurationPasswords { get; set; }
        public DbSet<ConfigurationSession> ConfigurationSessions { get; set; }
        public DbSet<ConfigurationLock> ConfigurationLocks { get; set; }
        public DbSet<Actee> Actees { get; set; }
        public DbSet<Service> Services { get; set; }
        public DbSet<UserProperty> UserProperties { get; set; }
        public DbSet<UserBiometric> UserBiometrics { get; set; }
        public DbSet<BiometricType> BiometricTypes { get; set; }
        public DbSet<ApplicationPackage> ApplicationPackages { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<LoginPolicy> LoginPolicies { get; set; }
        public DbSet<Mask> Masks { get; set; }
        public DbSet<Menu> Menus { get; set; }
        public DbSet<VerificationCode> VerificationCodes { get; set; }
        public DbSet<OauthToken> OauthTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Relationships
            #region User and UserProperty Relationship (One-to-Many)
            modelBuilder.Entity<User>()
                .HasOne(u => u.UserProperty)
                .WithOne(up => up.User)
                .HasForeignKey<UserProperty>(up => up.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            #endregion

            #region User and LoginPolicy Relationship (One-to-Many)
            modelBuilder.Entity<User>()
                .HasOne(u => u.LoginPolicy) 
                .WithOne(lp => lp.User)        
                .HasForeignKey<LoginPolicy>(lp => lp.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            #endregion

            #region UserRole and User Relationship (One-to-Many)
            modelBuilder.Entity<UserRole>()
                .HasOne(ur => ur.User)
                .WithOne(u => u.UserRole)
                .HasForeignKey<UserRole>(ur => ur.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            #endregion

            #region UserRole and Role Relationship (Many-to-One)
            modelBuilder.Entity<UserRole>()
                .HasOne(ur => ur.Role)
                .WithMany(r => r.UserRoles)
                .HasForeignKey(ur => ur.RoleId)
                .OnDelete(DeleteBehavior.Cascade);
            #endregion

            #region UserProperty and ConfigurationPassword Relationship (Many-to-One)
            modelBuilder.Entity<UserProperty>()
                .HasOne(up => up.ConfigurationPassword)
                .WithMany(cp => cp.UserProperties)
                .HasForeignKey(up => up.ConfigurationPasswordId)
                .OnDelete(DeleteBehavior.Cascade);
            #endregion

            // Seeding data
            DateTime specificTime = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc);  // January 1st, 2024, 12:00 PM UTC

modelBuilder.Entity<User>().HasData(new User(
    id: 1,
    uuid: "43t8haoghaioergh",
    firstName: "Admin",
    lastName: "User",
    nationalCode: "1234567890",
    email: "admin@example.com",
    mobile: "09389074038",
    primaryKey: "admin-primary-key",
    ipRange: "0.0.0.0",
    loginAttempt: 0,
    picture: null,
    pictureType: null,
    scheduled: "00:00-23:59",
    status: StatusTypes.Active,
    twoFactor: false,
    description: "Default admin user",
    createDate: specificTime,
    modifyDate: specificTime,
    deleteDate: null,
    deleteUser: null,
    modifyUser: null,
    userName: "admin_user",  // Seeding the UserName
    userProperty: null,  // Will be seeded separately
    userRole: null,  // Will be seeded separately
    loginPolicy: null  // Will be seeded separately
));

            #region SeedUserProperty
            modelBuilder.Entity<UserProperty>().HasData(new UserProperty(
                userId: 1,
                password: "123123123",  
                configurationPasswordId: 1
            ));
            #endregion

            #region SeedLoginPolicy
            modelBuilder.Entity<LoginPolicy>().HasData(new LoginPolicy(
                id: 1,
                lockTypes: LockTypes.None,
                userId: 1,
                lockStartDateTime: specificTime,
                lockEndDateTime: specificTime.AddMinutes(30),
                createDate: specificTime,
                modifyDate: specificTime,
                deleteDate: null,  
                deleteUser: null,  
                modifyUser: null   
            ));
            #endregion

            #region SeedUserRole
            modelBuilder.Entity<UserRole>().HasData(new UserRole(
                id: 1,
                userId: 1,
                roleId: 1,  
                isDefault: true,
                createDate: specificTime,
                modifyDate: specificTime,
                deleteDate: null,
                deleteUser: null,
                modifyUser: null
            ));
            #endregion

            base.OnModelCreating(modelBuilder);
        }
    }
}
