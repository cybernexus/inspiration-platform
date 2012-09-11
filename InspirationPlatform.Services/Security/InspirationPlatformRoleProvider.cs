using System;
using System.Globalization;
using System.Linq;
using System.Web.Security;
using InspirationPlatform.Core.DataModel.Users;
using InspirationPlatform.Services.Users;

namespace InspirationPlatform.Services.Security
{
    public class InspirationPlatformRoleProvider : RoleProvider
    {
        private readonly IUserService _userService;

        public InspirationPlatformRoleProvider(IUserService userService)
        {
            _userService = userService;
        }

        public override string ApplicationName
        {
            get
            {
                return GetType().Assembly.GetName().Name.ToString(CultureInfo.InvariantCulture);
            }
            set { throw new NotImplementedException(); }
        }

        public override bool RoleExists(string roleName)
        {
            if (string.IsNullOrEmpty(roleName))
            {
                return false;
            }

            var role = _userService.FindUserRoleByRoleName(roleName);

            if (role != null)
                return true;

            return false;
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            if (string.IsNullOrEmpty(username))
            {
                return false;
            }
            if (string.IsNullOrEmpty(roleName))
            {
                return false;
            }

            var user = _userService.FindUserByUserName(username);
            if (user == null)
                return false;

            var role = _userService.FindUserRoleByRoleName(roleName);
            if (role == null)
                return false;

            return user.UserRoles.Contains(role);
        }

        public override string[] GetAllRoles()
        {
            return _userService.GetAllUserRoles().Select(ur => ur.RoleName).ToArray();
        }

        public override string[] GetUsersInRole(string roleName)
        {
            if (string.IsNullOrEmpty(roleName))
                return null;

            var role = _userService.FindUserRoleByRoleName(roleName);
            return role == null ? null : role.Users.Select(u => u.Email).ToArray();
        }

        public override string[] GetRolesForUser(string username)
        {
            if (string.IsNullOrEmpty(username))
                return null;

            var user = _userService.FindUserByUserName(username);
            return user == null ? null : user.UserRoles.Select(ur => ur.RoleName).ToArray();
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            if (string.IsNullOrEmpty(roleName))
                return null;

            if (string.IsNullOrEmpty(usernameToMatch))
                return null;

            var role = _userService.FindUserRoleByRoleName(roleName);
            if (role == null)
                return null;

            return role.Users.Where(u => u.Email.Contains(usernameToMatch)).Select(u => u.Email).ToArray();
        }

        public override void CreateRole(string roleName)
        {
            if (!string.IsNullOrEmpty(roleName))
            {
                var role = _userService.FindUserRoleByRoleName(roleName);
                if (role == null)
                {
                    var newRole = new UserRole
                    {
                        RoleName = roleName
                    };
                    _userService.InsertRole(newRole);
                }
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            if (string.IsNullOrEmpty(roleName))
                return false;

            var role = _userService.FindUserRoleByRoleName(roleName);
            if (role == null)
                return false;

            if (throwOnPopulatedRole)
            {
                if (role.Users.Any())
                    return false;
            }
            else
            {
                role.Users.Clear();
            }

            _userService.DeleteRole(role);
            return true;
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            var users = _userService.GetAllUsers().Where(u => usernames.Contains(u.Email)).ToList();
            var roles = _userService.GetAllUserRoles().Where(r => roleNames.Contains(r.RoleName)).ToList();

            foreach (var user in users)
            {
                foreach (var userRole in roles)
                {
                    if (!user.UserRoles.Contains(userRole))
                    {
                        user.UserRoles.Add(userRole);
                    }
                }
            }
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            foreach (String username in usernames)
            {
                var user = _userService.FindUserByUserName(username);
                if (user != null)
                {
                    foreach (var roleName in roleNames)
                    {
                        var role = _userService.FindUserRoleByRoleName(roleName);
                        if (role != null)
                        {
                            user.UserRoles.Remove(role);
                        }
                    }
                }
            }
        }
    }
}