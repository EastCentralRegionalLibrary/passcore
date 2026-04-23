# Testing PassCore

This document describes how to run tests for PassCore, including backend unit tests and frontend E2E tests.

## Prerequisites

- .NET 8.0 SDK or later
- Node.js 22.x or later
- npm

## Backend Testing

Backend tests are written using xUnit and can be run using the .NET CLI:

```bash
dotnet test
```

## Frontend E2E Testing

E2E tests use Playwright and run against a running instance of the PassCore backend. For testing purposes, a `DebugPasswordChangeProvider` is used to simulate various password change scenarios without requiring a real Active Directory or LDAP server.

### 1. Build the Backend

Build the backend in `Debug` configuration:

```bash
dotnet build src/Unosquare.PassCore.Web/Unosquare.PassCore.Web.csproj -c Debug
```

### 2. Install Frontend Dependencies

```bash
cd src/Unosquare.PassCore.Web/ClientApp
npm install
npx playwright install --with-deps chromium
```

### 3. Start the Backend in Test Mode

The backend should be started with the `Test` environment to enable the debug provider and use the test settings:

```bash
# From the root of the repository
ASPNETCORE_ENVIRONMENT=Test dotnet run --project src/Unosquare.PassCore.Web/Unosquare.PassCore.Web.csproj --configuration Debug --no-build
```

### 4. Run Playwright Tests

In a separate terminal:

```bash
cd src/Unosquare.PassCore.Web/ClientApp
npx playwright test
```

## Continuous Integration (CI)

The CI pipeline is configured in `.github/workflows/ci-testing.yml`. It automatically runs:
1. Backend unit tests.
2. Frontend E2E tests using the steps described above in a headless environment.

On failure, Playwright reports and test results are uploaded as GitHub Action artifacts for debugging.
