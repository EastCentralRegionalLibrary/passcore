using System;

namespace Unosquare.PassCore.Common.Exceptions;

public class PasswordChangeException : Exception
{
    public PasswordChangeException() : base() { }
    public PasswordChangeException(string message) : base(message) { }
    public PasswordChangeException(string message, Exception innerException) : base(message, innerException) { }
}

public class InvalidCredentialsException : PasswordChangeException
{
    public InvalidCredentialsException() : base() { }
    public InvalidCredentialsException(string message) : base(message) { }
    public InvalidCredentialsException(string message, Exception innerException) : base(message, innerException) { }
}

public class PasswordPolicyViolationException : PasswordChangeException
{
    public ApiErrorCode ErrorCode { get; }
    public PasswordPolicyViolationException() : base() { ErrorCode = ApiErrorCode.ComplexPassword; }
    public PasswordPolicyViolationException(string message) : base(message) { ErrorCode = ApiErrorCode.ComplexPassword; }
    public PasswordPolicyViolationException(string message, Exception innerException) : base(message, innerException) { ErrorCode = ApiErrorCode.ComplexPassword; }
    public PasswordPolicyViolationException(string message, ApiErrorCode errorCode) : base(message)
    {
        ErrorCode = errorCode;
    }
}

public class UserNotFoundException : PasswordChangeException
{
    public UserNotFoundException() : base() { }
    public UserNotFoundException(string message) : base(message) { }
    public UserNotFoundException(string message, Exception innerException) : base(message, innerException) { }
}

public class DirectoryUnavailableException : PasswordChangeException
{
    public DirectoryUnavailableException() : base() { }
    public DirectoryUnavailableException(string message) : base(message) { }
    public DirectoryUnavailableException(string message, Exception innerException) : base(message, innerException) { }
}
