# PassCore Front-End Testing Harness Review

## Current Test Coverage State

The current E2E test suite covers the primary "Happy Path" and a common "Error Path" using the `DebugPasswordChangeProvider`:

1.  **Successful Password Change**: Verifies that valid credentials (including domain) lead to a success message.
2.  **Invalid Credentials**: Verifies that a specific username (`invalidCredentials@test.com`) triggers the expected error alert on the front-end.

The backend unit tests cover the logic of the `DebugPasswordChangeProvider` itself, ensuring it correctly simulates latency, pwned password checks, and forced errors.

## Limitations

- **Hardcoded Usernames**: The current E2E tests rely on specific usernames being mapped to error codes in `appsettings.Test.json`.
- **Minimal Coverage**: Only two scenarios are covered in E2E. Other error codes (e.g., complexity, distance, pwned) are not currently tested via the UI.
- **Environment Dependency**: Tests require the backend to be running on `http://localhost:5000` (configurable in `playwright.config.ts`).
- **Browser Coverage**: Currently only tested against Chromium in CI to save time/resources.

## Recommendations

1.  **Expand E2E Scenarios**: Add tests for password complexity failures, mismatched passwords, and pwned password alerts to ensure all UI feedback mechanisms work correctly.
2.  **Dynamic Error Injection**: Consider a way to inject error scenarios more dynamically without relying solely on `appsettings.json` mappings, perhaps via a dedicated test-only API endpoint if necessary.
3.  **Cross-Browser Testing**: Enable testing for Firefox and Webkit in CI to ensure front-end compatibility across different engines.
4.  **Visual Regression Testing**: Use Playwright's screenshot comparison features to prevent unintended UI shifts in future updates.
5.  **Integration with Docker**: The smoke test in `build_docker_validate.yml` could be extended to run the full E2E suite against the production Docker image (using the LDAP provider with a mock LDAP server like `osixia/openldap`).
