using System;
using System.Globalization;
using System.Linq;
using System.Web.Security;
using InspirationPlatform.Core.DataModel.Users;
using InspirationPlatform.Services.Users;

namespace InspirationPlatform.Services.Security
{
    public class InspirationPlatformMembershipProvider : MembershipProvider
    {
        private readonly IUserService _userService;

        public InspirationPlatformMembershipProvider(IUserService userService)
        {
            _userService = userService;
        }

        #region Properties

        public override string ApplicationName
        {
            get
            {
                return GetType().Assembly.GetName().Name.ToString(CultureInfo.InvariantCulture);
            }
            set { throw new NotImplementedException(); }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return 5; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return 0; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return 6; }
        }

        public override int PasswordAttemptWindow
        {
            get { return 0; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return MembershipPasswordFormat.Hashed; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return String.Empty; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return true; }
        }

        #endregion

        #region Functions

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            if (string.IsNullOrEmpty(username))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }
            if (string.IsNullOrEmpty(password))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            if (string.IsNullOrEmpty(email))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            string HashedPassword = Crypto.HashPassword(password);
            if (HashedPassword.Length > 128)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            var user = _userService.FindUserByUserName(username);
            if (user != null)
            {
                status = MembershipCreateStatus.DuplicateUserName;
                return null;
            }

            var newUser = new User
                {
                    Password = HashedPassword,
                    IsApproved = isApproved,
                    Email = email,
                    CreateDate = DateTime.UtcNow,
                    LastPasswordChangedDate = DateTime.UtcNow,
                    PasswordFailuresSinceLastSuccess = 0,
                    LastLoginDate = DateTime.UtcNow,
                    LastActivityDate = DateTime.UtcNow,
                    LastLockoutDate = DateTime.UtcNow,
                    IsLockedOut = false,
                    LastPasswordFailureDate = DateTime.UtcNow
                };

            _userService.InsertUser(newUser);
            status = MembershipCreateStatus.Success;
            return new MembershipUser(Membership.Provider.Name, newUser.Email, newUser.Id, newUser.Email, null, null, newUser.IsApproved, newUser.IsLockedOut, newUser.CreateDate.Value, newUser.LastLoginDate.Value, newUser.LastActivityDate.Value, newUser.LastPasswordChangedDate.Value, newUser.LastLockoutDate.Value);
        }

        public override bool ValidateUser(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            if (string.IsNullOrEmpty(password))
                return false;

            var user = _userService.FindUserByUserName(username);
            if (user == null)
                return false;

            if (!user.IsApproved)
                return false;

            if (user.IsLockedOut)
                return false;

            var hashedPassword = user.Password;
            var verificationSucceeded = (hashedPassword != null && Crypto.VerifyHashedPassword(hashedPassword, password));
            if (verificationSucceeded)
            {
                user.PasswordFailuresSinceLastSuccess = 0;
                user.LastLoginDate = DateTime.UtcNow;
                user.LastActivityDate = DateTime.UtcNow;
            }

            int failures = user.PasswordFailuresSinceLastSuccess;
            if (failures < MaxInvalidPasswordAttempts)
            {
                user.PasswordFailuresSinceLastSuccess += 1;
                user.LastPasswordFailureDate = DateTime.UtcNow;
            }
            else if (failures >= MaxInvalidPasswordAttempts)
            {
                user.LastPasswordFailureDate = DateTime.UtcNow;
                user.LastLockoutDate = DateTime.UtcNow;
                user.IsLockedOut = true;
            }

            _userService.UpdateUser(user);
            return verificationSucceeded;
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            if (string.IsNullOrEmpty(username))
                return null;

            var user = _userService.FindUserByUserName(username);

            if (user != null)
            {
                if (userIsOnline)
                {
                    user.LastActivityDate = DateTime.UtcNow;
                    _userService.UpdateUser(user);
                }
                return new MembershipUser(Membership.Provider.Name, user.Email, user.Id, user.Email, null, null, user.IsApproved, user.IsLockedOut, user.CreateDate.Value, user.LastLoginDate.Value, user.LastActivityDate.Value, user.LastPasswordChangedDate.Value, user.LastLockoutDate.Value);
            }

            return null;
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            if (providerUserKey is Guid) { }
            else
            {
                return null;
            }
            var user = _userService.GetUserById(Convert.ToInt64(providerUserKey));
            if (user != null)
            {
                if (userIsOnline)
                {
                    user.LastActivityDate = DateTime.UtcNow;
                    _userService.UpdateUser(user);
                }
                return new MembershipUser(Membership.Provider.Name, user.Email, user.Id, user.Email, null, null, user.IsApproved, user.IsLockedOut, user.CreateDate.Value, user.LastLoginDate.Value, user.LastActivityDate.Value, user.LastPasswordChangedDate.Value, user.LastLockoutDate.Value);
            }

            return null;
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            if (string.IsNullOrEmpty(oldPassword))
                return false;

            if (string.IsNullOrEmpty(newPassword))
                return false;

            var user = _userService.FindUserByUserName(username);
            if (user == null)
                return false;

            var hashedPassword = user.Password;
            Boolean verificationSucceeded = (hashedPassword != null && Crypto.VerifyHashedPassword(hashedPassword, oldPassword));
            if (verificationSucceeded)
            {
                user.PasswordFailuresSinceLastSuccess = 0;
            }
            else
            {
                int Failures = user.PasswordFailuresSinceLastSuccess;
                if (Failures < MaxInvalidPasswordAttempts)
                {
                    user.PasswordFailuresSinceLastSuccess += 1;
                    user.LastPasswordFailureDate = DateTime.UtcNow;
                }
                else if (Failures >= MaxInvalidPasswordAttempts)
                {
                    user.LastPasswordFailureDate = DateTime.UtcNow;
                    user.LastLockoutDate = DateTime.UtcNow;
                    user.IsLockedOut = true;
                }
                return false;
            }
            var newHashedPassword = Crypto.HashPassword(newPassword);
            if (newHashedPassword.Length > 128)
            {
                return false;
            }
            user.Password = newHashedPassword;
            user.LastPasswordChangedDate = DateTime.UtcNow;
            _userService.UpdateUser(user);

            return true;
        }

        public override bool UnlockUser(string userName)
        {
            var user = _userService.FindUserByUserName(userName);
            if (user != null)
            {
                user.IsLockedOut = false;
                user.PasswordFailuresSinceLastSuccess = 0;
                _userService.UpdateUser(user);
                return true;
            }
            return false;
        }

        public override int GetNumberOfUsersOnline()
        {
            DateTime DateActive = DateTime.UtcNow.Subtract(TimeSpan.FromMinutes(Convert.ToDouble(Membership.UserIsOnlineTimeWindow)));
            return _userService.GetAllUsers().Count(u => u.LastActivityDate > DateActive);
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            var user = _userService.FindUserByUserName(username);


            if (user != null)
            {
                _userService.DeleteUser(user);
                return true;
            }
            return false;
        }

        public override string GetUserNameByEmail(string email)
        {
            return email;
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            var membershipUsers = new MembershipUserCollection();
            var allUsers = _userService.GetAllUsers();
            totalRecords = allUsers.Count(Usr => Usr.Email == emailToMatch);
            var users =
                allUsers.Where(u => u.Email == emailToMatch).OrderBy(usrn => usrn.Email).Skip(
                    pageIndex*pageSize).Take(pageSize);

            foreach (var user in users)
            {
                membershipUsers.Add(new MembershipUser(Membership.Provider.Name, user.Email, user.Id, user.Email, null, null, user.IsApproved, user.IsLockedOut, user.CreateDate.Value, user.LastLoginDate.Value, user.LastActivityDate.Value, user.LastPasswordChangedDate.Value, user.LastLockoutDate.Value));
            }

            return membershipUsers;
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            var membershipUsers = new MembershipUserCollection();
            var allUsers = _userService.GetAllUsers();
            totalRecords = allUsers.Count(Usr => Usr.Email == usernameToMatch);
            var users =
                allUsers.Where(u => u.Email == usernameToMatch).OrderBy(usrn => usrn.Email).Skip(
                    pageIndex * pageSize).Take(pageSize);

            foreach (var user in users)
            {
                membershipUsers.Add(new MembershipUser(Membership.Provider.Name, user.Email, user.Id, user.Email, null, null, user.IsApproved, user.IsLockedOut, user.CreateDate.Value, user.LastLoginDate.Value, user.LastActivityDate.Value, user.LastPasswordChangedDate.Value, user.LastLockoutDate.Value));
            }

            return membershipUsers;
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            var  membershipUsers = new MembershipUserCollection();
            var allUsers = _userService.GetAllUsers();
            totalRecords = allUsers.Count();

            foreach (var user in allUsers)
            {
                membershipUsers.Add(new MembershipUser(Membership.Provider.Name, user.Email, user.Id, user.Email, null, null, user.IsApproved, user.IsLockedOut, user.CreateDate.Value, user.LastLoginDate.Value, user.LastActivityDate.Value, user.LastPasswordChangedDate.Value, user.LastLockoutDate.Value));
            }
            return membershipUsers;
        }

        #endregion

        #region Not Supported

        //CodeFirstMembershipProvider does not support password retrieval scenarios.
        public override bool EnablePasswordRetrieval
        {
            get { return false; }
        }
        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException("Consider using methods from WebSecurity module.");
        }

        //CodeFirstMembershipProvider does not support password reset scenarios.
        public override bool EnablePasswordReset
        {
            get { return false; }
        }
        public override string ResetPassword(string username, string answer)
        {
            throw new NotSupportedException("Consider using methods from WebSecurity module.");
        }

        //CodeFirstMembershipProvider does not support question and answer scenarios.
        public override bool RequiresQuestionAndAnswer
        {
            get { return false; }
        }
        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException("Consider using methods from WebSecurity module.");
        }

        //CodeFirstMembershipProvider does not support UpdateUser because this method is useless.
        public override void UpdateUser(MembershipUser user)
        {
            throw new NotSupportedException();
        }

        #endregion
    }
}