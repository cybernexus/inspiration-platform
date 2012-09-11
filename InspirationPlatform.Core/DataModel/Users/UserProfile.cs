using System;
using System.ComponentModel.DataAnnotations;

namespace InspirationPlatform.Core.DataModel.Users
{
    public class UserProfile : BaseEntity
    {
        public virtual string Name { get; set; }
        public virtual string Alias { get; set; }
        public virtual DateTime BirthDate { get; set; }

        [Required]
        public virtual User User { get; set; }

    }
}
