using System;
using Unosquare.PassCore.Common.Exceptions;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

public class ApiErrorMapperTests
{
    [Fact]
    public void Map_InvalidCredentialsException()
    {
        var ex = new InvalidCredentialsException("Invalid");
        var item = ApiErrorMapper.Map(ex);
        Assert.Equal(ApiErrorCode.InvalidCredentials, item.ErrorCode);
        Assert.Equal("Invalid", item.Message);
    }

    [Fact]
    public void Map_PasswordPolicyViolationException()
    {
        var ex = new PasswordPolicyViolationException("Policy", ApiErrorCode.MinimumScore);
        var item = ApiErrorMapper.Map(ex);
        Assert.Equal(ApiErrorCode.MinimumScore, item.ErrorCode);
        Assert.Equal("Policy", item.Message);
    }

    [Fact]
    public void Map_UserNotFoundException()
    {
        var ex = new UserNotFoundException("Not found");
        var item = ApiErrorMapper.Map(ex);
        Assert.Equal(ApiErrorCode.UserNotFound, item.ErrorCode);
        Assert.Equal("Not found", item.Message);
    }

    [Fact]
    public void Map_DirectoryUnavailableException()
    {
        var ex = new DirectoryUnavailableException("Unavailable", new Exception());
        var item = ApiErrorMapper.Map(ex);
        Assert.Equal(ApiErrorCode.LdapProblem, item.ErrorCode);
        Assert.Equal("Unavailable", item.Message);
    }

    [Fact]
    public void Map_GenericException()
    {
        var ex = new Exception("Generic");
        var item = ApiErrorMapper.Map(ex);
        Assert.Equal(ApiErrorCode.Generic, item.ErrorCode);
        Assert.Equal("Generic", item.Message);
    }
}
