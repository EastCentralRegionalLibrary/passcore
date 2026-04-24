using System;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Base class for password change related exceptions.
/// </summary>
public abstract class PasswordChangeException : Exception
{
    protected PasswordChangeException(string message)
        : base(message)
    {
    }

    protected PasswordChangeException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    protected PasswordChangeException()
    {
    }
}

/// <summary>
/// Exception thrown when invalid credentials are provided.
/// </summary>
public class InvalidCredentialsException : PasswordChangeException
{
    public InvalidCredentialsException(string message = "Invalid credentials")
        : base(message)
    {
    }

    public InvalidCredentialsException()
        : base("Invalid credentials")
    {
    }

    public InvalidCredentialsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when the new password violates a policy.
/// </summary>
public class PasswordPolicyViolationException : PasswordChangeException
{
    public PasswordPolicyViolationException(ApiErrorCode errorCode, string message = "Password policy violation")
        : base(message)
    {
        ErrorCode = errorCode;
    }

    public PasswordPolicyViolationException()
        : base("Password policy violation")
    {
    }

    public PasswordPolicyViolationException(string message)
        : base(message)
    {
    }

    public PasswordPolicyViolationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ApiErrorCode ErrorCode { get; }
}

/// <summary>
/// Exception thrown when the user is not found.
/// </summary>
public class UserNotFoundException : PasswordChangeException
{
    public UserNotFoundException(string message = "User not found")
        : base(message)
    {
    }

    public UserNotFoundException()
        : base("User not found")
    {
    }

    public UserNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when the directory service is unavailable.
/// </summary>
public class DirectoryUnavailableException : PasswordChangeException
{
    public DirectoryUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException!)
    {
    }

    public DirectoryUnavailableException()
        : base("Directory unavailable")
    {
    }

    public DirectoryUnavailableException(string message)
        : base(message)
    {
    }
}
