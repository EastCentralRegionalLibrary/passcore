using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using LdapRemoteCertificateValidationCallback =
    Novell.Directory.Ldap.RemoteCertificateValidationCallback;

namespace Zyborg.PassCore.PasswordProvider.LDAP;

/// <summary>
/// Represents a LDAP password change provider using Novell LDAP Connection.
/// </summary>
/// <seealso cref="IPasswordChangeProvider" />
public class LdapPasswordChangeProvider : PasswordChangeProviderBase
{
    private readonly LdapPasswordChangeOptions _options;

    // First find user DN by username (SAM Account Name)
    private readonly LdapSearchConstraints _searchConstraints = new(
        0,
        0,
        LdapSearchConstraints.DerefNever,
        1000,
        true,
        1,
        null,
        10);

    // TODO: is this related to https://github.com/dsbenghe/Novell.Directory.Ldap.NETStandard/issues/101 at all???
    // Had to mark this as nullable.
    private LdapRemoteCertificateValidationCallback? _ldapRemoteCertValidator;

    /// <summary>
    /// Initializes a new instance of the <see cref="LdapPasswordChangeProvider"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The _options.</param>
    /// <param name="policies">The password policies.</param>
    public LdapPasswordChangeProvider(
        ILogger<LdapPasswordChangeProvider> logger,
        IOptions<LdapPasswordChangeOptions> options,
        IEnumerable<IPasswordPolicy> policies)
        : base(logger, policies)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        Init();
    }

    /// <inheritdoc />
    protected override Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            var cleanUsername = CleaningUsername(context.Username);

            var searchFilter = _options.LdapSearchFilter.Replace("{Username}", cleanUsername, StringComparison.Ordinal);

            using var ldap = BindToLdap();
            var search = ldap.Search(
                _options.LdapSearchBase,
                LdapConnection.ScopeSub,
                searchFilter,
                new[] { "distinguishedName" },
                false,
                _searchConstraints);

            // We cannot use search.Count here -- apparently it does not
            // wait for the results to return before resolving the count
            // but fortunately hasMore seems to block until final result
            if (!search.HasMore())
            {
                if (_options.HideUserNotFound)
                    throw new InvalidCredentialsException();

                throw new UserNotFoundException("Username could not be located");
            }

            if (search.Count > 1)
            {
                // Hopefully this should not ever happen if AD is preserving SAM Account Name
                // uniqueness constraint, but just in case, handling this corner case
                throw new UserNotFoundException("Multiple matching user entries resolved");
            }

            var userDN = search.Next().Dn;

            if (_options.LdapChangePasswordWithDelAdd)
            {
                ChangePasswordDelAdd(context.CurrentPassword, context.NewPassword, ldap, userDN);
            }
            else
            {
                ChangePasswordReplace(context.NewPassword, ldap, userDN);
            }

            if (_options.LdapStartTls)
                ldap.StopTls();

            ldap.Disconnect();
        }
        catch (LdapException ex)
        {
            throw TranslateLdapException(ex);
        }
        catch (ApiErrorException ex)
        {
            throw new PasswordPolicyViolationException(ex.Message, ex.ErrorCode);
        }

        return Task.CompletedTask;
    }

    private static void ChangePasswordReplace(string newPassword, LdapConnection ldap, string userDN)
    {
        // If you don't have the rights to Add and/or Delete the Attribute, you might have the right to change the password-attribute.
        // In this case uncomment the next 2 lines and comment the region 'Change Password by Delete/Add'
        var attribute = new LdapAttribute("userPassword", newPassword);
        var ldapReplace = new LdapModification(LdapModification.Replace, attribute);
        ldap.Modify(userDN, new[] { ldapReplace }); // Change with Replace
    }

    private static void ChangePasswordDelAdd(string currentPassword, string newPassword, LdapConnection ldap, string userDN)
    {
        var oldPassBytes = Encoding.Unicode.GetBytes($@"""{currentPassword}""");
        var newPassBytes = Encoding.Unicode.GetBytes($@"""{newPassword}""");

        var oldAttr = new LdapAttribute("unicodePwd", oldPassBytes);
        var newAttr = new LdapAttribute("unicodePwd", newPassBytes);

        var ldapDel = new LdapModification(LdapModification.Delete, oldAttr);
        var ldapAdd = new LdapModification(LdapModification.Add, newAttr);
        ldap.Modify(userDN, new[] { ldapDel, ldapAdd }); // Change with Delete/Add
    }

    private static Exception TranslateLdapException(LdapException ex)
    {
        // If the LDAP server returned an error, it will be formatted
        // similar to this:
        //    "0000052D: AtrErr: DSID-03191083, #1:\n\t0: 0000052D: DSID-03191083, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)\n\0"
        //
        // The leading number before the ':' is the Win32 API Error Code in HEX
        if (ex.LdapErrorMessage == null)
        {
            return new DirectoryUnavailableException("Unexpected null exception", ex);
        }

        var m = Regex.Match(ex.LdapErrorMessage, "([0-9a-fA-F]+):", RegexOptions.None, TimeSpan.FromMilliseconds(100));

        if (!m.Success)
        {
            return new DirectoryUnavailableException($"Unexpected error: {ex.LdapErrorMessage}", ex);
        }

        var errCodeString = m.Groups[1].Value;
        var errCode = int.Parse(errCodeString, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        var err = Win32ErrorCode.ByCode(errCode);

        if (err == null)
        {
            return new DirectoryUnavailableException($"Unexpected Win32 API error; error code: {errCodeString}", ex);
        }

        return new InvalidCredentialsException($"Resolved Win32 API Error: code={err.Code} name={err.CodeName} desc={err.Description}");
    }

    private string CleaningUsername(string username)
    {
        var cleanUsername = username;
        var index = cleanUsername.IndexOf('@', StringComparison.Ordinal);
        if (index >= 0)
            cleanUsername = cleanUsername[..index];

        // Must sanitize the username to eliminate the possibility of injection attacks:
        //    * https://docs.microsoft.com/en-us/windows/desktop/adschema/a-samaccountname
        //    * https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb726984(v=technet.10)
        var invalidChars = "\"/\\[]:;|=,+*?<>\r\n\t".ToCharArray();

        if (cleanUsername.IndexOfAny(invalidChars) >= 0)
            throw new ApiErrorException("Username contains one or more invalid characters", ApiErrorCode.InvalidCredentials);

        // LDAP filters require escaping of some special chars:
        //    * http://www.ldapexplorer.com/en/manual/109010000-ldap-filter-syntax.htm
        var escape = "()&|=><!*/\\".ToCharArray();
        var escapeIndex = cleanUsername.IndexOfAny(escape);

        if (escapeIndex < 0)
            return cleanUsername;

        var buff = new StringBuilder();
        var maxLen = cleanUsername.Length;
        var copyFrom = 0;

        while (escapeIndex >= 0)
        {
            buff.Append(cleanUsername.AsSpan(copyFrom, escapeIndex - copyFrom));
            buff.Append($"\\{cleanUsername[escapeIndex]:X}");
            copyFrom = escapeIndex + 1;
            escapeIndex = cleanUsername.IndexOfAny(escape, copyFrom);
        }

        if (copyFrom < maxLen)
            buff.Append(cleanUsername.AsSpan(copyFrom));

        return buff.ToString();
    }

    private void Init()
    {
        // Validate required options
        if (_options.LdapIgnoreTlsErrors || _options.LdapIgnoreTlsValidation)
            _ldapRemoteCertValidator = CustomServerCertValidation;

        if (_options.LdapHostnames?.Length < 1)
        {
            throw new ArgumentException("Options must specify at least one LDAP hostname",
                nameof(_options.LdapHostnames));
        }

        if (string.IsNullOrEmpty(_options.LdapUsername))
        {
            throw new ArgumentException("Options missing or invalid LDAP bind distinguished name (DN)",
                nameof(_options.LdapUsername));
        }

        if (string.IsNullOrEmpty(_options.LdapPassword))
        {
            throw new ArgumentException("Options missing or invalid LDAP bind password",
                nameof(_options.LdapPassword));
        }

        if (string.IsNullOrEmpty(_options.LdapSearchBase))
        {
            throw new ArgumentException("Options must specify LDAP search base",
                nameof(_options.LdapSearchBase));
        }

        if (string.IsNullOrWhiteSpace(_options.LdapSearchFilter))
        {
            throw new ArgumentException(
                $"No {nameof(_options.LdapSearchFilter)} is set. Fill attribute {nameof(_options.LdapSearchFilter)} in file appsettings.json",
                nameof(_options.LdapSearchFilter));
        }

        if (!_options.LdapSearchFilter.Contains("{Username}", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The {nameof(_options.LdapSearchFilter)} should include {{Username}} value in the template string",
                nameof(_options.LdapSearchFilter));
        }
    }

    private LdapConnection BindToLdap()
    {
        var ldap = new LdapConnection();
        if (_ldapRemoteCertValidator != null)
            ldap.UserDefinedServerCertValidationDelegate += _ldapRemoteCertValidator;

        ldap.SecureSocketLayer = _options.LdapSecureSocketLayer;

        string? bindHostname = null;

        foreach (var h in _options.LdapHostnames)
        {
            try
            {
                ldap.Connect(h, _options.LdapPort);
                bindHostname = h;
                break;
            }
            catch (LdapException)
            {
                // Silence connect errors here as they are retried or handled at the end
            }
        }

        if (string.IsNullOrEmpty(bindHostname))
        {
            throw new ApiErrorException("Failed to connect to any configured hostname", ApiErrorCode.InvalidCredentials);
        }

        if (_options.LdapStartTls)
            ldap.StartTls();

        ldap.Bind(_options.LdapUsername, _options.LdapPassword);

        return ldap;
    }

    /// <summary>
    /// Custom server certificate validation logic that handles our special
    /// cases based on configuration.  This implements the logic of either
    /// ignoring just untrusted root errors or ignoring all TLS errors.
    /// </summary>
    /// <param name="sender">The sender.</param>
    /// <param name="certificate">The certificate.</param>
    /// <param name="chain">The chain.</param>
    /// <param name="sslPolicyErrors">The SSL policy errors.</param>
    /// <returns><c>true</c> if the certificate validation was successful.</returns>
    private bool CustomServerCertValidation(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) =>
        _options.LdapIgnoreTlsErrors || sslPolicyErrors == SslPolicyErrors.None || chain.ChainStatus
            .Any(x => x.Status switch
            {
                X509ChainStatusFlags.UntrustedRoot when _options.LdapIgnoreTlsValidation => true,
                _ => x.Status == X509ChainStatusFlags.NoError
            });
}
