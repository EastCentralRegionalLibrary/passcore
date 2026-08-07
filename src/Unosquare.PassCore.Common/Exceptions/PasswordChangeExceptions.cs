using System;

namespace Unosquare.PassCore.Common.Exceptions;

/// <summary>
/// Exception thrown when a password change operation fails.
/// </summary>
public class PasswordChangeException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordChangeException"/> class.
    /// </summary>
    public PasswordChangeException() : base() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordChangeException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public PasswordChangeException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordChangeException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PasswordChangeException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when user credentials are invalid.
/// </summary>
public class InvalidCredentialsException : PasswordChangeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidCredentialsException"/> class.
    /// </summary>
    public InvalidCredentialsException() : base() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidCredentialsException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public InvalidCredentialsException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidCredentialsException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public InvalidCredentialsException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when a password change policy is violated.
/// </summary>
public class PasswordPolicyViolationException : PasswordChangeException
{
    /// <summary>
    /// Gets the API error code associated with this violation.
    /// </summary>
    public ApiErrorCode ErrorCode { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordPolicyViolationException"/> class.
    /// </summary>
    public PasswordPolicyViolationException() : base() { ErrorCode = ApiErrorCode.ComplexPassword; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordPolicyViolationException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public PasswordPolicyViolationException(string message) : base(message) { ErrorCode = ApiErrorCode.ComplexPassword; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordPolicyViolationException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PasswordPolicyViolationException(string message, Exception innerException) : base(message, innerException) { ErrorCode = ApiErrorCode.ComplexPassword; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordPolicyViolationException"/> class with a specified error message and API error code.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The API error code.</param>
    public PasswordPolicyViolationException(string message, ApiErrorCode errorCode) : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordPolicyViolationException"/> class with a specified error message, API error code, and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The API error code.</param>
    /// <param name="innerException">The inner exception.</param>
    public PasswordPolicyViolationException(string message, ApiErrorCode errorCode, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Exception thrown when a user is not found.
/// </summary>
public class UserNotFoundException : PasswordChangeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserNotFoundException"/> class.
    /// </summary>
    public UserNotFoundException() : base() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserNotFoundException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public UserNotFoundException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="UserNotFoundException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public UserNotFoundException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when the directory is unavailable.
/// </summary>
public class DirectoryUnavailableException : PasswordChangeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryUnavailableException"/> class.
    /// </summary>
    public DirectoryUnavailableException() : base() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryUnavailableException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public DirectoryUnavailableException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryUnavailableException"/> class with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public DirectoryUnavailableException(string message, Exception innerException) : base(message, innerException) { }
}
