using System;
using System.Collections.Generic;
using InspirationPlatform.Core.DataModel.Users;

namespace InspirationPlatform.Services.Users
{
    public interface IUserService
    {
        IList<User> GetAllUsers();
        User GetUserById(Int64 id);
        User FindUserByUserName(string username);
        void InsertUser(User user);
        void DeleteUser(User user);
        void UpdateUser(User user);
        #region Role Methods

        
        IList<UserRole> GetAllUserRoles();
        UserRole FindUserRoleByRoleName(string roleName);
        void InsertRole(UserRole role);
        void DeleteRole(UserRole role);

        #endregion
    }
}