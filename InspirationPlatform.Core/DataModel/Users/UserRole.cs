using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace InspirationPlatform.Core.DataModel.Users
{
    public class UserRole : BaseEntity
    {
        [Required]
        public virtual string RoleName { get; set; }

        public virtual string Description { get; set; }

        public virtual ICollection<User> Users { get; set; }
    }
}