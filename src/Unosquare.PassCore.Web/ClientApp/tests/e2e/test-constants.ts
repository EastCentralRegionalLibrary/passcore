export const TEST_USERS = {
  SUCCESS: {
    username: 'someuser@test.com',
    currentPassword: 'OldPassword123!',
    newPassword: 'SafePassword99!@',
  },
  INVALID_CREDENTIALS: {
    username: 'invalidCredentials@test.com',
    currentPassword: 'wrong',
    newPassword: 'SafePassword99!@',
  },
  USER_NOT_FOUND: {
    username: 'userNotFound@test.com',
    currentPassword: 'OldPassword123!',
    newPassword: 'SafePassword99!@',
  },
  COMPLEX_PASSWORD: {
    username: 'complexPassword@test.com',
    currentPassword: 'OldPassword123!',
    newPassword: 'short',
  },
  RESTRICTED_GROUP: {
    username: 'restrictedUser@test.com',
    currentPassword: 'OldPassword123!',
    newPassword: 'SafePassword99!@',
  },
  NOT_ALLOWED_GROUP: {
    username: 'notAllowedUser@test.com',
    currentPassword: 'OldPassword123!',
    newPassword: 'SafePassword99!@',
  },
  ALLOWED_USER: {
    username: 'allowedUser@test.com',
    currentPassword: 'OldPassword123!',
    newPassword: 'SafePassword99!@',
  },
};

export const ALERTS = {
  SUCCESS: 'You have changed your password successfully.',
  INVALID_CREDENTIALS: 'You need to provide the correct current password.',
  USER_NOT_FOUND: 'We could not find your user account.',
  COMPLEX_PASSWORD: 'Failed due to password complexity policies',
  NOT_ALLOWED: 'You are not allowed to change your password. Please contact your system administrator.',
};
