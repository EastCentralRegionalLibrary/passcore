using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common;

public class PasswordChangeContext
{
    public PasswordChangeContext(string username, string currentPassword, string newPassword, ClientSettings clientSettings, string? correlationId = null)
    {
        Username = username;
        CurrentPassword = currentPassword;
        NewPassword = newPassword;
        ClientSettings = clientSettings;
        CorrelationId = correlationId;
    }

    public string Username { get; }
    public string CurrentPassword { get; }
    public string NewPassword { get; }
    public ClientSettings ClientSettings { get; }
    public string? CorrelationId { get; }
}
