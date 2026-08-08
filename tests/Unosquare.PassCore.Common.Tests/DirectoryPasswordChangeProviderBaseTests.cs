using System;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Covers the seam <see cref="DirectoryPasswordChangeProviderBase"/> exposes for
/// translating a transport exception into a domain exception:
/// <see cref="DirectoryPasswordChangeProviderBase.TryGetTransportWin32Code"/> and
/// <see cref="DirectoryPasswordChangeProviderBase.TranslateDirectoryException(Exception, DirectoryActor, out DirectoryFailureClass)"/>.
/// The only genuinely provider-specific part of error handling is how a
/// Win32 code is recovered from that provider's transport, so these tests
/// pin the default (Win32Exception / FACILITY_WIN32 HRESULT) behaviour and
/// confirm an overriding subclass takes precedence.
/// </summary>
public class DirectoryPasswordChangeProviderBaseTests
{
    private sealed class FakeAppSettings : IAppSettings
    {
        public ErrorDisclosureMode ErrorDisclosureMode { get; set; }

        public bool AllowAdministrativeReset { get; set; }

        public string DefaultDomain { get; set; } = string.Empty;

        public int LdapPort { get; set; }

        public string[] LdapHostnames { get; set; } = Array.Empty<string>();

        public string LdapPassword { get; set; } = string.Empty;

        public string LdapUsername { get; set; } = string.Empty;
    }

    private class TestProvider : DirectoryPasswordChangeProviderBase
    {
        public TestProvider(IAppSettings settings)
            : base(NullLogger.Instance, settings)
        {
        }

        protected override int? ReadMinPwdLength() => null;

        public override Task<IResolvedGroupMembership> ResolveMembershipAsync(string username) =>
            throw new NotImplementedException();

        /// <summary>
        /// Lets each test supply the body of <see cref="ChangeDirectoryPasswordCore"/>
        /// so the sealed terminal catch in <see cref="DirectoryPasswordChangeProviderBase.ChangePasswordCore"/>
        /// can be exercised through the public entry point.
        /// </summary>
        public Func<Task>? OnChangeCore { get; set; }

        protected override Task ChangeDirectoryPasswordCore(PasswordChangeContext context, CancellationToken cancellationToken) =>
            OnChangeCore?.Invoke() ?? Task.CompletedTask;

        public Exception TestTranslateDirectoryException(
            Exception exception, DirectoryActor actor, out DirectoryFailureClass failureClass) =>
            TranslateDirectoryException(exception, actor, out failureClass);

        public Exception TestTranslateDirectoryException(Exception exception, DirectoryActor actor) =>
            TranslateDirectoryException(exception, actor);

        public Exception TestTranslateDirectoryException(Exception exception) =>
            TranslateDirectoryException(exception);
    }

    /// <summary>
    /// A subclass that recovers its Win32 code from a made-up transport shape,
    /// standing in for LDAP's AD-extended-error-string parsing without pulling
    /// that provider into this project.
    /// </summary>
    private sealed class OverridingProvider : TestProvider
    {
        public OverridingProvider(IAppSettings settings)
            : base(settings)
        {
        }

        protected override bool TryGetTransportWin32Code(Exception exception, out int win32Code)
        {
            if (exception is FakeTransportException fake)
            {
                win32Code = fake.Code;
                return true;
            }

            return base.TryGetTransportWin32Code(exception, out win32Code);
        }
    }

    private sealed class FakeTransportException : Exception
    {
        public FakeTransportException(int code) => Code = code;

        public int Code { get; }
    }

    private static TestProvider MakeProvider(ErrorDisclosureMode mode = ErrorDisclosureMode.Hardened) =>
        new(new FakeAppSettings { ErrorDisclosureMode = mode });

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void TranslateDirectoryException_Win32Exception_RecoversCodeViaDefaultHook(ErrorDisclosureMode mode)
    {
        var provider = MakeProvider(mode);
        var inner = new Win32Exception(0x52E);

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        Assert.IsType<InvalidCredentialsException>(translated);
        Assert.Equal(DirectoryFailureClass.Credentials, failureClass);
        Assert.Same(inner, translated.InnerException);
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void TranslateDirectoryException_FacilityWin32HResult_RecoversCodeViaDefaultHook(ErrorDisclosureMode mode)
    {
        var provider = MakeProvider(mode);
        var inner = new HResultException(unchecked((int)0x800708C5)); // 0x8C5, NERR_PasswordTooShort

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        Assert.IsType<PasswordPolicyViolationException>(translated);
        Assert.Equal(DirectoryFailureClass.NewPasswordPolicy, failureClass);
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void TranslateDirectoryException_NoRecoverableCode_YieldsDirectoryUnavailableAndInfrastructure(ErrorDisclosureMode mode)
    {
        var provider = MakeProvider(mode);
        var inner = new InvalidOperationException("no code here");

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        var unavailable = Assert.IsType<DirectoryUnavailableException>(translated);
        Assert.Equal(DirectoryFailureClass.Infrastructure, failureClass);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, unavailable.Message);
        Assert.Same(inner, unavailable.InnerException);
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void TranslateDirectoryException_ServiceAccountActor_CollapsesCredentialsCodeToInfrastructure(ErrorDisclosureMode mode)
    {
        var provider = MakeProvider(mode);
        var inner = new Win32Exception(0x52E);

        var translated = provider.TestTranslateDirectoryException(
            inner, DirectoryActor.ServiceAccount, out var failureClass);

        Assert.IsType<DirectoryUnavailableException>(translated);
        Assert.Equal(DirectoryFailureClass.Infrastructure, failureClass);
    }

    [Fact]
    public void TranslateDirectoryException_OverridingSubclass_HookTakesPrecedenceOverDefault()
    {
        var provider = new OverridingProvider(new FakeAppSettings { ErrorDisclosureMode = ErrorDisclosureMode.Hardened });
        var inner = new FakeTransportException(0x52E);

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        Assert.IsType<InvalidCredentialsException>(translated);
        Assert.Equal(DirectoryFailureClass.Credentials, failureClass);
        Assert.Same(inner, translated.InnerException);
    }

    /// <summary>
    /// Confirms the base's default hook is still reachable from the override
    /// when the exception is not the shape it recognizes, since the override
    /// falls back to <c>base.TryGetTransportWin32Code</c>.
    /// </summary>
    [Fact]
    public void TranslateDirectoryException_OverridingSubclass_FallsBackToDefaultHookForUnrecognizedShape()
    {
        var provider = new OverridingProvider(new FakeAppSettings { ErrorDisclosureMode = ErrorDisclosureMode.Hardened });
        var inner = new Win32Exception(0x52E);

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        Assert.IsType<InvalidCredentialsException>(translated);
        Assert.Equal(DirectoryFailureClass.Credentials, failureClass);
    }

    [Fact]
    public void TranslateDirectoryException_NullException_ThrowsArgumentNullException()
    {
        var provider = MakeProvider();

        Assert.Throws<ArgumentNullException>(
            () => provider.TestTranslateDirectoryException(null!, DirectoryActor.User, out _));
    }

    /// <summary>
    /// Existence (0x525, ERROR_NO_SUCH_USER) is the classic mode-divergence
    /// row: Informative discloses that the account was not found; Hardened
    /// folds it into invalid credentials so an attacker cannot enumerate
    /// accounts.
    /// </summary>
    [Theory]
    [InlineData(ErrorDisclosureMode.Informative, typeof(UserNotFoundException))]
    [InlineData(ErrorDisclosureMode.Hardened, typeof(InvalidCredentialsException))]
    public void TranslateDirectoryException_ExistenceCode_RespectsDisclosureModeFromSettings(
        ErrorDisclosureMode mode, Type expectedType)
    {
        var provider = MakeProvider(mode);
        var inner = new Win32Exception(0x525); // ERROR_NO_SUCH_USER

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        Assert.IsType(expectedType, translated);
        Assert.Equal(DirectoryFailureClass.Existence, failureClass);
    }

    /// <summary>
    /// AccountState (0x775, ERROR_ACCOUNT_LOCKED_OUT) is the other
    /// mode-divergence row: Informative discloses the policy-violation reason
    /// with <see cref="ApiErrorCode.ChangeNotPermitted"/>; Hardened folds it
    /// into invalid credentials.
    /// </summary>
    [Fact]
    public void TranslateDirectoryException_AccountStateCode_Informative_YieldsChangeNotPermittedPolicyViolation()
    {
        var provider = MakeProvider(ErrorDisclosureMode.Informative);
        var inner = new Win32Exception(0x775); // ERROR_ACCOUNT_LOCKED_OUT

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        var policyViolation = Assert.IsType<PasswordPolicyViolationException>(translated);
        Assert.Equal(ApiErrorCode.ChangeNotPermitted, policyViolation.ErrorCode);
        Assert.Equal(DirectoryFailureClass.AccountState, failureClass);
    }

    [Fact]
    public void TranslateDirectoryException_AccountStateCode_Hardened_YieldsInvalidCredentials()
    {
        var provider = MakeProvider(ErrorDisclosureMode.Hardened);
        var inner = new Win32Exception(0x775); // ERROR_ACCOUNT_LOCKED_OUT

        var translated = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        Assert.IsType<InvalidCredentialsException>(translated);
        Assert.Equal(DirectoryFailureClass.AccountState, failureClass);
    }

    /// <summary>
    /// The two migrated call sites rely on the one-arg convenience overload
    /// defaulting to <see cref="DirectoryActor.User"/>; pin that default by
    /// comparing both overloads against the three-arg form directly.
    /// </summary>
    [Fact]
    public void TranslateDirectoryException_ActorOverload_MatchesThreeArgOverloadWithSameActor()
    {
        var provider = MakeProvider();
        var inner = new Win32Exception(0x52E);

        var viaActorOverload = provider.TestTranslateDirectoryException(inner, DirectoryActor.ServiceAccount);
        var viaFullOverload = provider.TestTranslateDirectoryException(
            inner, DirectoryActor.ServiceAccount, out var failureClass);

        Assert.Equal(viaFullOverload.GetType(), viaActorOverload.GetType());
        Assert.Equal(DirectoryFailureClass.Infrastructure, failureClass);
    }

    [Fact]
    public void TranslateDirectoryException_NoArgOverload_DefaultsToUserActor()
    {
        var provider = MakeProvider();
        var inner = new Win32Exception(0x52E);

        var viaNoArgOverload = provider.TestTranslateDirectoryException(inner);
        var viaUserActor = provider.TestTranslateDirectoryException(inner, DirectoryActor.User, out var failureClass);

        Assert.Equal(viaUserActor.GetType(), viaNoArgOverload.GetType());
        Assert.Equal(DirectoryFailureClass.Credentials, failureClass);
        Assert.IsType<InvalidCredentialsException>(viaNoArgOverload);
    }

    /// <summary>
    /// Covers <see cref="DirectoryPasswordChangeProviderBase.ChangePasswordCore"/>,
    /// the terminal catch both directory providers used to duplicate, driven
    /// through the public entry point so the whole pipeline —
    /// <see cref="PasswordChangeProviderBase.PerformPasswordChangeAsync"/> down
    /// to <see cref="ApiErrorMapper"/> — is exercised rather than just the
    /// catch clause in isolation.
    /// </summary>
    [Fact]
    public async Task PerformPasswordChangeAsync_CoreThrowsPasswordChangeExceptionSubtype_ReachesCallerUnwrapped()
    {
        var provider = MakeProvider();
        var core = new InvalidCredentialsException("bad credentials");
        provider.OnChangeCore = () => throw core;

        var result = await provider.PerformPasswordChangeAsync("user", "current", "new");

        Assert.False(result.IsSuccessful);
        var error = Assert.Single(result.Errors);
        Assert.Equal(ApiErrorCode.InvalidCredentials, error.ErrorCode);
        Assert.Equal(core.Message, error.Message);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_CoreThrowsPlainException_BecomesDirectoryUnavailable()
    {
        var provider = MakeProvider();
        var core = new InvalidOperationException("unexpected failure");
        provider.OnChangeCore = () => throw core;

        var result = await provider.PerformPasswordChangeAsync("user", "current", "new");

        Assert.False(result.IsSuccessful);
        var error = Assert.Single(result.Errors);
        Assert.Equal(ApiErrorCode.LdapProblem, error.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, error.Message);
    }

    /// <summary>
    /// The negative case that pins the documented rule: the terminal catch
    /// constructs <see cref="DirectoryUnavailableException"/> directly and does
    /// not re-scan the exception chain for a Win32 code, so even a
    /// <see cref="Win32Exception"/> carrying a genuine credentials code
    /// (0x52E, ERROR_LOGON_FAILURE) must still surface as
    /// <see cref="ApiErrorCode.LdapProblem"/> when it reaches this catch —
    /// never <see cref="ApiErrorCode.InvalidCredentials"/>. Recovering that
    /// code is the job of a typed transport catch inside
    /// <see cref="DirectoryPasswordChangeProviderBase.ChangeDirectoryPasswordCore"/>,
    /// upstream of here; an exception reaching the terminal catch is by
    /// definition unexpected and non-directory-typed.
    /// </summary>
    [Fact]
    public async Task PerformPasswordChangeAsync_CoreThrowsWin32ExceptionDirectly_StillBecomesDirectoryUnavailable()
    {
        var provider = MakeProvider();
        var core = new Win32Exception(0x52E); // ERROR_LOGON_FAILURE
        provider.OnChangeCore = () => throw core;

        var result = await provider.PerformPasswordChangeAsync("user", "current", "new");

        Assert.False(result.IsSuccessful);
        var error = Assert.Single(result.Errors);
        Assert.Equal(ApiErrorCode.LdapProblem, error.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, error.Message);
    }

    private sealed class HResultException : Exception
    {
        public HResultException(int hresult, string message = "test", Exception? inner = null)
            : base(message, inner)
        {
            HResult = hresult;
        }
    }
}
