﻿using System.Data.Entity;
using InspirationPlatform.Core.DataModel.Users;

namespace InspirationPlatform.Core.Context
{
    public class DataContext : DbContext
    {
        //protected override void OnModelCreating(DbModelBuilder modelBuilder)
        //{
        //    modelBuilder.Conventions.Remove<System.Data.Entity.Infrastructure.IncludeMetadataConvention>();
        //}

        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
    }
}
