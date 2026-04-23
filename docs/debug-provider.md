# Debug Password Change Provider

The Debug Password Change Provider is designed to facilitate frontend development and automated testing without requiring a real Active Directory or LDAP connection. It allows for deterministic behavior through configuration.

## Enabling the Debug Provider

The Debug Provider is automatically enabled in `Development` and `Test` environments when the `DEBUG` compilation symbol is present (which is the default in the project configuration).

**Security Warning:** The application will throw an exception and fail to start if it detects that the Debug Provider is being registered in a `Production` environment.

## Configuration

You can configure the behavior of the Debug Provider in your `appsettings.Development.json` or `appsettings.Test.json` file.

```json
"DebugProviderOptions": {
  "EnablePwnedCheck": false,
  "SimulateLatencyMs": 500,
  "DefaultErrorCode": null,
  "ForcedErrors": {
    "error": "Generic",
    "changeNotPermitted": "ChangeNotPermitted",
    "userNotFound": "UserNotFound"
  }
}
```

### Options

| Option | Type | Description |
| :--- | :--- | :--- |
| `EnablePwnedCheck` | `boolean` | Whether to simulate a Pwned Password check. |
| `SimulateLatencyMs` | `int` | Number of milliseconds to delay the response to simulate network/processing latency. |
| `DefaultErrorCode` | `string?` | If set, every request that doesn't match a forced error will return this `ApiErrorCode`. |
| `ForcedErrors` | `Dictionary<string, ApiErrorCode>` | A mapping of usernames to specific error codes. |

## Usage in Tests

The `Test` environment uses `appsettings.Test.json`. By setting specific usernames in `ForcedErrors`, you can test how the frontend handles various error scenarios.

### Example Usernames

By default, the following usernames are handled even without explicit `ForcedErrors` configuration (legacy support):

- `error`: Returns `Generic` error.
- `changeNotPermitted`: Returns `ChangeNotPermitted` error.
- `fieldMismatch`: Returns `FieldMismatch` error.
- `invalidCredentials`: Returns `InvalidCredentials` error.
- `userNotFound`: Returns `UserNotFound` error.
- `pwnedPassword`: Returns `PwnedPassword` error.

## Running in Test Mode Locally

To run the web application with the `Test` environment settings:

```bash
cd src/Unosquare.PassCore.Web
dotnet run --launch-profile Test
```

This will start the app on `http://localhost:5000`.
