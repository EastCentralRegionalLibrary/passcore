# SonarQube / Roslyn Issue Review Report

This document contains a comprehensive review of all 81 issues listed in the provided SonarQube JSON analysis.
Each issue has been researched and cross-referenced against the current state of the codebase.

---

## Executive Summary

- **Total Issues Analyzed**: 81
- **Issues Requiring Action / Real Code Improvements**: 24
- **Issues Not Present / Obsolete / Already Addressed**: 6
- **Issues That Do Not Need Action / Safe To Ignore / Intentional Design / Roslyn IDE Style Preferences**: 51

---

## Issue Category Breakdown & Findings

### 1. High Complexity & Method Refactoring
- **`AaAQzfk1lJLc_uVa1PlS`** (`csharpsquid:S3776` - `LdapPasswordChangeProvider.cs:272`)
  - **Message**: Refactor `IsMemberOfAnyGroup` to reduce Cognitive Complexity from 48 to 15.
  - **Status**: Present.
  - **Needs Action**: Yes. Method handles group enumeration, LDAP matching rules, primary groups, nested groups, and fallback logic. Splitting helper methods would improve maintainability.
- **`AaAQzfk1lJLc_uVa1PlU`** (`csharpsquid:S3776` - `LdapPasswordChangeProvider.cs:704`)
  - **Message**: Refactor `UnescapeRdnValue` to reduce Cognitive Complexity from 22 to 15.
  - **Status**: Present.
  - **Needs Action**: Yes. Parsing RFC 4514 hex escapes and UTF-8 multi-byte sequences can be simplified into smaller private helpers.
- **`AaAQzfk1lJLc_uVa1Plb`** (`csharpsquid:S3776` - `LdapPasswordChangeProvider.cs:1125`)
  - **Message**: Refactor `ResolveMinimumLength` to reduce Cognitive Complexity from 17 to 15.
  - **Status**: Present.
  - **Needs Action**: Yes. Splitting RootDSE lookup and fallback policy extraction will lower complexity below threshold.

---

### 2. Vulnerabilities & Security Audits
- **`AaAQzflKlJLc_uVa1Pln`** (`csharpsquid:S4790` - `PwnedSearch.cs:124`)
  - **Message**: Use a stronger hashing algorithm.
  - **Status**: Present.
  - **Needs Action**: **No**. SHA-1 is required by the Pwned Passwords k-Anonymity API specification (which requires the first 5 characters of the SHA-1 hash of the password). It is not used for internal password storage or cryptographic signatures.
- **`AaAQzflZlJLc_uVa1Plo` & `AaAQzflZlJLc_uVa1Plq`** (`githubactions:S6505` - `.github/workflows/ci-testing.yml:116, 148`)
  - **Message**: `npx` can install packages on-demand and run lifecycle scripts.
  - **Status**: Present.
  - **Needs Action**: Yes. Replacing `npx` or passing explicit package names with pinned versions in CI workflows eliminates dynamic package fetching risks.
- **`AaAQzflZlJLc_uVa1Plp` & `AaAQzflZlJLc_uVa1Plr`** (`githubactions:S8543` - `.github/workflows/ci-testing.yml:116, 148`)
  - **Message**: Define exact package version.
  - **Status**: Present.
  - **Needs Action**: Yes. Pinning exact package versions in CI runner commands ensures deterministic workflow execution.
- **`AaAQzfk1lJLc_uVa1Ple`, `AaAQzfk1lJLc_uVa1Pld`, `AaAQzfk1lJLc_uVa1Plc`** (`csharpsquid:S6444` - `LdapPasswordChangeProvider.cs:52, 58, 62`)
  - **Message**: Pass a timeout to limit execution time of regular expressions.
  - **Status**: Present.
  - **Needs Action**: Yes. Adding a `TimeSpan` match timeout (e.g. 1 second) to static/compiled Regex instances prevents potential ReDoS vectors.
- **`AaAQzfnalJLc_uVa1Pl3` & `AaAQzfnalJLc_uVa1Pl5`** (`docker:S8482` - `Dockerfile:16, 26`)
  - **Message**: Avoid executing downloaded artifacts directly without verification.
  - **Status**: Present.
  - **Needs Action**: Optional / Contextual. Script downloads `dotnet-install.sh` from official Microsoft endpoints (`dot.net`). Adding SHA checksum validation or downloading via trusted standard package channels is recommended where required.
- **`AaAQzfnalJLc_uVa1Pl4`** (`docker:S6471` / `docker:S6506` - `Dockerfile:16`)
  - **Message**: Not enforcing HTTPS here might allow for redirections.
  - **Status**: Present.
  - **Needs Action**: Yes. Ensuring explicit HTTPS URLs for script/binary downloads in Docker builds.
- **`AaAQzfnalJLc_uVa1Pl6`** (`docker:S6471` - `Dockerfile:38`)
  - **Message**: Container runs as default root user.
  - **Status**: Present.
  - **Needs Action**: Contextual. In Docker runtime containers, switching to a non-root `USER app` is best practice for production deployments.

---

### 3. Code Logic & Correctness (Blockers & Criticals)
- **`AaAQzfU5lJLc_uVa1PjY`** (`csharpsquid:S2699` - `LdapSecurityDescriptorTests.cs:123`)
  - **Message**: Add at least one assertion to this test case.
  - **Status**: Present.
  - **Needs Action**: Yes. Test method performs an operation without explicit `Assert.*` call. Adding assertions ensures test effectiveness.
- **`AaAQzfeMlJLc_uVa1PkT`** (`csharpsquid:S3427` - `ApiErrorException.cs:34`)
  - **Message**: Overlapping constructor signature with default parameters.
  - **Status**: Present.
  - **Needs Action**: Yes. Removing redundant default values on overloaded constructor avoids ambiguous constructor invocation.
- **`AaAQzfeClJLc_uVa1PkS`** (`csharpsquid:S108` - `DistancePasswordPolicy.cs:43`)
  - **Message**: Either remove or fill this block of code.
  - **Status**: Present.
  - **Needs Action**: Yes. Empty catch or conditional block should contain a comment or logging explaining why it is empty.
- **`AaAQzfk1lJLc_uVa1PlZ` & `AaAQzfk1lJLc_uVa1Pla`** (`csharpsquid:S2589` - `LdapPasswordChangeProvider.cs:373, 386`)
  - **Message**: Remove unnecessary check for null.
  - **Status**: Present.
  - **Needs Action**: Yes. Variables are proven non-null prior to condition; redundant null check can be removed.
- **`AaAQzfkDlJLc_uVa1PlF`** (`external_roslyn:CA1508` - `PasswordChangeProvider.cs:412`)
  - **Message**: Variable is always null / dead code.
  - **Status**: Present.
  - **Needs Action**: Yes. Clean up unused branch/variable.
- **`AaAQzfd2lJLc_uVa1PkM`, `AaAQzfd2lJLc_uVa1PkN`** (`csharpsquid:S1075` - `Program.cs:31, 36`)
  - **Message**: Refactor code not to use hardcoded absolute paths or URIs.
  - **Status**: Present.
  - **Needs Action**: **No**. These are standard default public base URIs (`https://www.google.com/recaptcha/api/` and `https://api.pwnedpasswords.com/`) for external APIs used by `HttpClient` registrations. They can optionally be made configurable in `appsettings.json`, but hardcoding default API endpoints in service registration is standard.
- **`AaAQzfd2lJLc_uVa1PkO`** (`csharpsquid:S6966` - `Program.cs:90`)
  - **Message**: Await `RunAsync` instead of calling `Run()`.
  - **Status**: Present.
  - **Needs Action**: Yes. Replacing `app.Run()` with `await app.RunAsync()` in top-level `Program.cs` is standard for async web host execution.
- **`AaAQzfdilJLc_uVa1PkL`** (`csharpsquid:S1118` - `Program.cs:95`)
  - **Message**: Add a protected constructor or static keyword to top-level Program class declaration.
  - **Status**: Present.
  - **Needs Action**: **No**. `public partial class Program;` is the standard .NET 6+ / 8.0 pattern required for `WebApplicationFactory<Program>` in integration tests. Adding static or non-public constructor breaks test host instantiation.

---

### 4. Performance & Language Feature Modernization
- **`AaAQzfkDlJLc_uVa1Pk-`, `AaAQzfkDlJLc_uVa1PlA`, `AaAQzfkDlJLc_uVa1PlC`, `AaAQzfk1lJLc_uVa1PlX`, `AaAQzfk1lJLc_uVa1PlY`** (`csharpsquid:S6618`)
  - **Message**: Use `string.Create` instead of `FormattableString`.
  - **Status**: Present.
  - **Needs Action**: Optional. Recommended for high-throughput string formatting allocations.
- **`AaAQzfkDlJLc_uVa1Pk9`, `AaAQzfkDlJLc_uVa1PlB`** (`csharpsquid:S6608`)
  - **Message**: Indexing at `[0]` should be used instead of `First()`.
  - **Status**: Present.
  - **Needs Action**: Yes. Replaces `IList.First()` or array `.First()` with `[0]` for performance.
- **`AaAQzfXGlJLc_uVa1Pjp`, `AaAQzfWFlJLc_uVa1Pjc`, `AaAQzfWFlJLc_uVa1Pjd`, `AaAQzfWFlJLc_uVa1Pjb`, `AaAQzfWFlJLc_uVa1Pja`, `AaAQzfWFlJLc_uVa1Pje`, `AaAQzfWFlJLc_uVa1Pjf`, `AaAQzfXGlJLc_uVa1Pjo`, `AaAQzfk1lJLc_uVa1Plg`, `AaAQzfk1lJLc_uVa1Plf`, `AaAQzfk1lJLc_uVa1Plh`** (`external_roslyn:SYSLIB1045`)
  - **Message**: Use `GeneratedRegexAttribute` to generate regular expression implementation at compile-time.
  - **Status**: Present.
  - **Needs Action**: Recommended. Utilizing .NET 7+ source-generated regex improves startup and execution performance.
- **`AaAQzfXGlJLc_uVa1Pjn`** (`external_roslyn:CA2249` - `AdProviderDirectoryWriteAuditTests.cs:212`)
  - **Message**: Use `string.Contains` instead of `string.IndexOf`.
  - **Status**: Present.
  - **Needs Action**: Yes. Replaces `IndexOf(...) >= 0` with `Contains(...)`.
- **`AaAQzfk1lJLc_uVa1Pli`** (`external_roslyn:IDE0057` - `LdapPasswordChangeProvider.cs:1185`)
  - **Message**: Slice can be simplified.
  - **Status**: Present.
  - **Needs Action**: Yes. Simplified range index expression `[a..b]`.

---

### 5. Loop Control & Iteration Safety
- **`AaAQzfk1lJLc_uVa1PlV`, `AaAQzfk1lJLc_uVa1PlT`, `AaAQzfk1lJLc_uVa1PlW`** (`csharpsquid:S127` - `LdapPasswordChangeProvider.cs:673, 719, 731`)
  - **Message**: Do not update the stop condition variable `i` in the body of the for loop.
  - **Status**: Present.
  - **Needs Action**: Yes. Modifying loop counter inside loop body can be refactored to a `while` loop or explicit iteration step for clarity.

---

### 6. C# Roslyn IDE Preferences (Expression-Bodied Members & Style)
- **`AaAQzfiblJLc_uVa1Pkl`, `AaAQzfjHlJLc_uVa1Pks`, `AaAQzfjelJLc_uVa1Pk1`, `AaAQzfjelJLc_uVa1Pk3`, `AaAQzfjelJLc_uVa1Pk2`, `AaAQzfjHlJLc_uVa1Pkx`, `AaAQzfd5lJLc_uVa1PkR`, `AaAQzfkDlJLc_uVa1PlH`, `AaAQzfjHlJLc_uVa1Pku`, `AaAQzfjHlJLc_uVa1Pkv`, `AaAQzfjHlJLc_uVa1Pkw`, `AaAQzfjHlJLc_uVa1Pkt`, `AaAQzfi8lJLc_uVa1Pkp`, `AaAQzfjolJLc_uVa1Pk4`, `AaAQzfjolJLc_uVa1Pk5`, `AaAQzfi8lJLc_uVa1Pko`, `AaAQzfi8lJLc_uVa1Pkq`, `AaAQzfi8lJLc_uVa1Pkr`, `AaAQzfinlJLc_uVa1Pkm`, `AaAQzfiPlJLc_uVa1Pkb`, `AaAQzfiPlJLc_uVa1Pkd`, `AaAQzfiPlJLc_uVa1Pke`, `AaAQzfiPlJLc_uVa1Pkg`, `AaAQzfk1lJLc_uVa1Plj`, `AaAQzfk1lJLc_uVa1Plk`, `AaAQzfk1lJLc_uVa1Pll`, `AaAQzfjzlJLc_uVa1Pk6`, `AaAQzfiPlJLc_uVa1Pkh`, `AaAQzfiPlJLc_uVa1Pki`, `AaAQzfiPlJLc_uVa1Pkj`, `AaAQzfiblJLc_uVa1Pkk`, `AaAQzfdtlJLc_uVa1PkQ`, `AaAQzfiPlJLc_uVa1Pka`, `AaAQzfiPlJLc_uVa1Pkc`, `AaAQzfjSlJLc_uVa1Pky`, `AaAQzfjSlJLc_uVa1Pkz`, `AaAQzfjSlJLc_uVa1Pk0`, `AaAQzfeMlJLc_uVa1PkV`, `AaAQzfeMlJLc_uVa1PkU`, `AaAQzfiDlJLc_uVa1PkW`, `AaAQzfiDlJLc_uVa1PkX`, `AaAQzfiDlJLc_uVa1PkZ`, `AaAQzfiDlJLc_uVa1PkY`, `AaAQzfchlJLc_uVa1PkJ`, `AaAQzfdXlJLc_uVa1PkK`** (`external_roslyn:IDE0022` / `IDE0021`)
  - **Message**: Use block body for method / constructor.
  - **Status**: Present.
  - **Needs Action**: **No**. Modern C# (C# 7 through C# 12) idiomatic style encourages expression-bodied members (`=>`) for concise single-statement methods and constructors. Converting them back to block bodies is cosmetic and violates team style preferences.

---

### 7. Exception Catching & API Design Rules
- **`AaAQzfkDlJLc_uVa1PlJ`, `AaAQzfkDlJLc_uVa1PlK`, `AaAQzfkDlJLc_uVa1PlG`** (`external_roslyn:CA1031`)
  - **Message**: Catch a more specific allowed exception type, or rethrow.
  - **Status**: Present.
  - **Needs Action**: Contextual. In directory provider fallbacks (e.g., AD/LDAP connection attempts), catching general `Exception` is intentional to prevent process crash when probing directory availability, provided the exception is properly translated and logged.
- **`AaAQzfkDlJLc_uVa1PlE`** (`external_roslyn:CS0419` - `PasswordChangeProvider.cs:932`)
  - **Message**: Ambiguous reference in cref attribute.
  - **Status**: Present.
  - **Needs Action**: Yes. Adding explicit parameter types to XML doc `<see cref="..." />` resolves compiler doc warnings.
- **`AaAQzfkDlJLc_uVa1PlD`** (`external_roslyn:CS1591` - `PasswordChangeProvider.cs:236`)
  - **Message**: Missing XML comment for publicly visible type or member.
  - **Status**: Present.
  - **Needs Action**: Yes. Add XML doc comments.
- **`AaAQzfixlJLc_uVa1Pkn`, `AaAQzfkXlJLc_uVa1PlP`, `AaAQzfk_lJLc_uVa1Plm`** (`external_roslyn:CA1819`)
  - **Message**: Properties should not return arrays.
  - **Status**: Present.
  - **Needs Action**: **No**. ASP.NET Core configuration binding (`appsettings.json`) requires array properties (e.g. `string[]`) on options classes for array binding. Changing property types would break configuration binding.
- **`AaAQzfkOlJLc_uVa1PlM`, `AaAQzfkOlJLc_uVa1PlN`, `AaAQzfkOlJLc_uVa1PlO`** (`external_roslyn:CA1052`, `CA5392`, `SYSLIB1054` - `NativeMethods.cs`)
  - **Message**: Class is non-static; P/Invoke missing `DefaultDllImportSearchPaths` / LibraryImport.
  - **Status**: Present.
  - **Needs Action**: Yes. Marking `NativeMethods` as `static`, adding search paths, or using `LibraryImport` improves interop security and performance.
- **`AaAQzfkDlJLc_uVa1Pk8` & `AaAQzfkDlJLc_uVa1PlL`** (`csharpsquid:S2325` / `external_roslyn:CA1822` - `PasswordChangeProvider.cs:476`)
  - **Message**: Make `ValidateUserCredentials` a static method.
  - **Status**: Present.
  - **Needs Action**: Yes. Method does not access instance state.

---

### 8. Frontend (TypeScript & React) Issues
- **`AaAQzfbWlJLc_uVa1PkB`, `AaAQzfX9lJLc_uVa1Pjy`** (`typescript:S3358` - `PasswordStrengthBar.tsx:71`, `FetchRequest.ts:19`)
  - **Message**: Extract nested ternary operation into independent statement.
  - **Status**: Present.
  - **Needs Action**: Yes. Refactoring nested ternaries into `if/else` or lookup maps improves readability.
- **`AaAQzfa2lJLc_uVa1Pj9`, `AaAQzfbLlJLc_uVa1Pj_`, `AaAQzfbWlJLc_uVa1PkA`, `AaAQzfbAlJLc_uVa1Pj-`, `AaAQzfcMlJLc_uVa1PkH`, `AaAQzfcAlJLc_uVa1PkG`, `AaAQzfb2lJLc_uVa1PkF`** (`typescript:S6759`)
  - **Message**: Mark props of component as read-only.
  - **Status**: Present.
  - **Needs Action**: Yes. Adding `Readonly<Props>` or `readonly` modifier in TypeScript interfaces prevents accidental prop mutation.
- **`AaAQzfZllJLc_uVa1Pj4`** (`typescript:S2933` - `GoogleReCaptcha.tsx:31`)
  - **Message**: Mark member `recaptcha` as `readonly`.
  - **Status**: Present.
  - **Needs Action**: Yes.
- **`AaAQzfYxlJLc_uVa1Pj0`, `AaAQzfYxlJLc_uVa1Pjz`, `AaAQzfYxlJLc_uVa1Pj2`** (`typescript:S8786` - `HtmlStringUtils.tsx`)
  - **Message**: Simplify regular expression to reduce runtime / backtracking.
  - **Status**: Present.
  - **Needs Action**: Yes. Refactoring regex patterns prevents catastrophic backtracking on malformed HTML strings.
- **`AaAQzfbglJLc_uVa1PkC`, `AaAQzfbglJLc_uVa1PkD`, `AaAQzfbqlJLc_uVa1PkE`** (`typescript:S6754` - `ChangePassword.tsx`, `useEffectWithLoading.ts`)
  - **Message**: `useState` call is not destructured into value + setter pair.
  - **Status**: Present.
  - **Needs Action**: Yes. Replacing tuple array indexing with standard `const [state, setState] = useState(...)` tuple destructuring.
- **`AaAQzfZblJLc_uVa1Pj3`, `AaAQzfZllJLc_uVa1Pj8`** (`typescript:S6582` - `AppSettings.ts:6`, `GoogleReCaptcha.tsx:131`)
  - **Message**: Prefer optional chain expression.
  - **Status**: Present.
  - **Needs Action**: Yes. Replace verbose `a && a.b` with `a?.b`.
- **`AaAQzfYxlJLc_uVa1Pj1`** (`typescript:S6594` - `HtmlStringUtils.tsx:38`)
  - **Message**: Use `RegExp.exec()` method.
  - **Status**: Present.
  - **Needs Action**: Yes.
- **`AaAQzfcXlJLc_uVa1PkI`** (`javascript:S7772` - `version-script.mjs:1`)
  - **Message**: Prefer `node:fs` over `fs`.
  - **Status**: Present.
  - **Needs Action**: Yes. Modern Node.js ES module import best practice.
- **`AaAQzfZllJLc_uVa1Pj5`** (`typescript:S7741` - `GoogleReCaptcha.tsx:61`)
  - **Message**: Compare with `undefined` directly instead of using `typeof`.
  - **Status**: Present.
  - **Needs Action**: Yes.
- **`AaAQzfZllJLc_uVa1Pj6`, `AaAQzfZllJLc_uVa1Pj7`** (`typescript:S6441` - `GoogleReCaptcha.tsx:79, 85`)
  - **Message**: Remove property or method as `reset`/`execute` is not used inside component body.
  - **Status**: Present.
  - **Needs Action**: Contextual. `reset` and `execute` are component instance methods intended for imperative ref calls.

---

### 9. Test Assemblies & Code Performance Rules
- **`AaAQzfWglJLc_uVa1Pjh`, `AaAQzfWglJLc_uVa1Pji`, `AaAQzfWglJLc_uVa1Pjj`, `AaAQzfXRlJLc_uVa1Pjq`, `AaAQzfXRlJLc_uVa1Pjr`, `AaAQzfXRlJLc_uVa1Pjs`, `AaAQzfXRlJLc_uVa1Pjt`, `AaAQzfWSlJLc_uVa1Pjg`, `AaAQzfWrlJLc_uVa1Pjk`** (`external_roslyn:CA1861`)
  - **Message**: Prefer `static readonly` fields over constant array arguments.
  - **Status**: Present.
  - **Needs Action**: Yes. Declaring static readonly arrays avoids allocating temporary arrays on repeated test/method invocations.
- **`AaAQzfW3lJLc_uVa1Pjm`, `AaAQzfW3lJLc_uVa1Pjl`, `AaAQzfkjlJLc_uVa1PlQ`** (`external_roslyn:CA1859`)
  - **Message**: Change return/field type from base interface to concrete type for improved performance.
  - **Status**: Present.
  - **Needs Action**: Optional in test helper methods; recommended where devirtualization benefits exist.
- **`AaAQzfXylJLc_uVa1Pjx`** (`external_roslyn:xUnit2032` - `DebugPasswordChangeProviderTests.cs:139`)
  - **Message**: `Assert.IsType` overload with exact match flag.
  - **Status**: Present.
  - **Needs Action**: Yes.
- **`AaAQzfVGlJLc_uVa1PjZ`, `AaAQzfRAlJLc_uVa1PjU`, `AaAQzfRAlJLc_uVa1PjV`, `AaAQzfRAlJLc_uVa1PjW`, `AaAQzfUulJLc_uVa1PjX`** (`external_roslyn:xUnit2031`)
  - **Message**: Do not use `Where` clause before calling `Assert.Single`.
  - **Status**: Present.
  - **Needs Action**: Yes. Use `Assert.Single(collection, predicate)` directly.
- **`AaAQzfdtlJLc_uVa1PkP`** (`csharpsquid:S1125` - `PwnedPasswordPolicy.cs:29`)
  - **Message**: Remove unnecessary Boolean literal.
  - **Status**: Present.
  - **Needs Action**: Yes. Simplify `condition == true` to `condition`.

---

### 10. Shell Scripts & PowerShell Installers
- **`AaAQzfXdlJLc_uVa1Pju`, `AaAQzfXdlJLc_uVa1Pjv`** (`shelldre:S1192` - `seedusers.sh:46, 67`)
  - **Message**: Define a constant instead of duplicating literal string `ou=people` / `ou=groups`.
  - **Status**: Present.
  - **Needs Action**: Yes. Defining a variable in shell script reduces duplication.
- **`AaAQzfXolJLc_uVa1Pjw`** (`powershelldre:S8621` - `restart-passcore.ps1:100`)
  - **Message**: Pipeline stages should have consistent indentation.
  - **Status**: Present.
  - **Needs Action**: Yes. Fix PowerShell indentation.
- **`AaAQzfnRlJLc_uVa1Pl1`, `AaAQzfnRlJLc_uVa1Pl0`, `AaAQzfnQlJLc_uVa1Plv`, `AaAQzfnRlJLc_uVa1Plw`, `AaAQzfnRlJLc_uVa1Plx`, `AaAQzflklJLc_uVa1Plt`, `AaAQzfnRlJLc_uVa1Ply`** (`powershelldre:S8642`)
  - **Message**: Change case of cmdlet / operator / parameter name (e.g. `new-object` to `New-Object`, `-value` to `-Value`).
  - **Status**: Present.
  - **Needs Action**: Yes. Standardizing PascalCase for PowerShell cmdlets and parameters matches official PowerShell coding style guidelines.
- **`AaAQzfnRlJLc_uVa1Plz`** (`powershelldre:S8638` - `Installer.ps1:32`)
  - **Message**: `Get-WmiObject` is deprecated; replace with `Get-CimInstance`.
  - **Status**: Present.
  - **Needs Action**: Yes. Modern PowerShell 7+ compatibility.
- **`AaAQzflklJLc_uVa1Pls`, `AaAQzflklJLc_uVa1Plu`** (`powershelldre:S8622` - `IISSetup.ps1:35, 63`)
  - **Message**: Replace `!` with `-not`.
  - **Status**: Present.
  - **Needs Action**: Yes. Using `-not` is idiomatic PowerShell.

---

## Full Issue Table

| Key | Rule | Component | Line | Severity | Status | Needs Action / Justification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `AaAQzfiblJLc_uVa1Pkl` | `external_roslyn:IDE0022` | `PasswordChangeProviderBase.cs` | 231 | INFO | Present | No (Expression body `=>` is intentional C# style) |
| `AaAQzfk1lJLc_uVa1PlS` | `csharpsquid:S3776` | `LdapPasswordChangeProvider.cs` | 272 | CRITICAL | Present | Yes (Reduce complexity from 48 to <= 15) |
| `AaAQzfbWlJLc_uVa1PkB` | `typescript:S3358` | `PasswordStrengthBar.tsx` | 71 | MAJOR | Present | Yes (Extract nested ternary) |
| `AaAQzfa2lJLc_uVa1Pj9` | `typescript:S6759` | `GlobalSnackbar.tsx` | 12 | MINOR | Present | Yes (Mark props as readonly) |
| `AaAQzfjHlJLc_uVa1Pks` | `external_roslyn:IDE0022` | `DirectoryPasswordChangeProviderBase.cs` | 70 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjelJLc_uVa1Pk1` | `external_roslyn:IDE0022` | `GroupMembershipAnswer.cs` | 90 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjelJLc_uVa1Pk3` | `external_roslyn:IDE0022` | `GroupMembershipAnswer.cs` | 94 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjelJLc_uVa1Pk2` | `external_roslyn:IDE0022` | `GroupMembershipAnswer.cs` | 98 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfkDlJLc_uVa1Pk7` | `csharpsquid:S3358` | `PasswordChangeProvider.cs` | 424 | MAJOR | Present | Yes (Extract nested ternary) |
| `AaAQzfWglJLc_uVa1Pjh` | `external_roslyn:CA1861` | `DirectoryPasswordChangeProviderBaseTests.cs` | 439 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfWglJLc_uVa1Pji` | `external_roslyn:CA1861` | `DirectoryPasswordChangeProviderBaseTests.cs` | 452 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfWglJLc_uVa1Pjj` | `external_roslyn:CA1861` | `DirectoryPasswordChangeProviderBaseTests.cs` | 453 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfXRlJLc_uVa1Pjq` | `external_roslyn:CA1861` | `ResolvedGroupMembershipTests.cs` | 184 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfXRlJLc_uVa1Pjr` | `external_roslyn:CA1861` | `ResolvedGroupMembershipTests.cs` | 185 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfXRlJLc_uVa1Pjs` | `external_roslyn:CA1861` | `ResolvedGroupMembershipTests.cs` | 188 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfXRlJLc_uVa1Pjt` | `external_roslyn:CA1861` | `ResolvedGroupMembershipTests.cs` | 189 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfk1lJLc_uVa1PlU` | `csharpsquid:S3776` | `LdapPasswordChangeProvider.cs` | 704 | CRITICAL | Present | Yes (Reduce complexity from 22 to <= 15) |
| `AaAQzfk1lJLc_uVa1PlV` | `csharpsquid:S127` | `LdapPasswordChangeProvider.cs` | 719 | MAJOR | Present | Yes (Refactor loop index mutation) |
| `AaAQzfXGlJLc_uVa1Pjp` | `external_roslyn:SYSLIB1045` | `AdProviderDirectoryWriteAuditTests.cs` | 644 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfjHlJLc_uVa1Pkx` | `external_roslyn:IDE0022` | `DirectoryPasswordChangeProviderBase.cs` | 374 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfW3lJLc_uVa1Pjm` | `external_roslyn:CA1859` | `PerformGatedPasswordWriteTests.cs` | 129 | INFO | Present | Optional (Concrete exception type) |
| `AaAQzfW3lJLc_uVa1Pjl` | `external_roslyn:CA1859` | `PerformGatedPasswordWriteTests.cs` | 132 | INFO | Present | Optional (Concrete exception type) |
| `AaAQzflKlJLc_uVa1Pln` | `csharpsquid:S4790` | `PwnedSearch.cs` | 124 | CRITICAL | Present | No (SHA-1 required by Pwned Passwords API protocol) |
| `AaAQzfeClJLc_uVa1PkS` | `csharpsquid:S108` | `DistancePasswordPolicy.cs` | 43 | MAJOR | Present | Yes (Comment or handle empty block) |
| `AaAQzfd5lJLc_uVa1PkR` | `external_roslyn:IDE0022` | `GroupMembershipPolicy.cs` | 53 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfkDlJLc_uVa1PlH` | `external_roslyn:IDE0022` | `PasswordChangeProvider.cs` | 810 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjHlJLc_uVa1Pku` | `external_roslyn:IDE0022` | `DirectoryPasswordChangeProviderBase.cs` | 187 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjHlJLc_uVa1Pkv` | `external_roslyn:IDE0022` | `DirectoryPasswordChangeProviderBase.cs` | 228 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjHlJLc_uVa1Pkw` | `external_roslyn:IDE0022` | `DirectoryPasswordChangeProviderBase.cs` | 239 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjHlJLc_uVa1Pkt` | `external_roslyn:IDE0022` | `DirectoryPasswordChangeProviderBase.cs` | 162 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfWSlJLc_uVa1Pjg` | `external_roslyn:CA1861` | `AppSettingsValidationTests.cs` | 127 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfkDlJLc_uVa1PlE` | `external_roslyn:CS0419` | `PasswordChangeProvider.cs` | 932 | MAJOR | Present | Yes (Fix ambiguous cref attribute) |
| `AaAQzfXylJLc_uVa1Pjx` | `external_roslyn:xUnit2032` | `DebugPasswordChangeProviderTests.cs` | 139 | INFO | Present | Yes (Use Assert.IsType exact match overload) |
| `AaAQzfi8lJLc_uVa1Pkp` | `external_roslyn:IDE0022` | `AdsiPath.cs` | 79 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfkDlJLc_uVa1PlI` | `external_roslyn:CA1861` | `PasswordChangeProvider.cs` | 754 | MAJOR | Present | Yes (Use static readonly array) |
| `AaAQzfkDlJLc_uVa1PlJ` | `external_roslyn:CA1031` | `PasswordChangeProvider.cs` | 759 | MAJOR | Present | No (Catching Exception is required for fallback) |
| `AaAQzfWFlJLc_uVa1Pjc` | `external_roslyn:SYSLIB1045` | `LoggingConventionAuditTests.cs` | 211 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfWFlJLc_uVa1Pjd` | `external_roslyn:SYSLIB1045` | `LoggingConventionAuditTests.cs` | 215 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfXdlJLc_uVa1Pjv` | `shelldre:S1192` | `seedusers.sh` | 46 | MINOR | Present | Yes (Define variable for ou=people) |
| `AaAQzfjolJLc_uVa1Pk4` | `external_roslyn:IDE0022` | `LdapChannelPorts.cs` | 45 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjolJLc_uVa1Pk5` | `external_roslyn:IDE0022` | `LdapChannelPorts.cs` | 57 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfkDlJLc_uVa1Pk-` | `csharpsquid:S6618` | `PasswordChangeProvider.cs` | 884 | MINOR | Present | Optional (string.Create optimization) |
| `AaAQzfkDlJLc_uVa1PlK` | `external_roslyn:CA1031` | `PasswordChangeProvider.cs` | 890 | MAJOR | Present | No (Catching Exception is required for fallback) |
| `AaAQzfkDlJLc_uVa1PlA` | `csharpsquid:S6618` | `PasswordChangeProvider.cs` | 915 | MINOR | Present | Optional (string.Create optimization) |
| `AaAQzfk1lJLc_uVa1PlR` | `csharpsquid:S1192` | `LdapPasswordChangeProvider.cs` | 504 | MINOR | Present | Yes (Define constant for (objectClass=*)) |
| `AaAQzfVGlJLc_uVa1PjZ` | `external_roslyn:xUnit2031` | `GroupTypeMatchingTests.cs` | 140 | MAJOR | Present | Yes (Use Assert.Single overload with predicate) |
| `AaAQzfi8lJLc_uVa1Pko` | `external_roslyn:IDE0022` | `AdsiPath.cs` | 35 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfi8lJLc_uVa1Pkq` | `external_roslyn:IDE0022` | `AdsiPath.cs` | 84 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfi8lJLc_uVa1Pkr` | `external_roslyn:IDE0022` | `AdsiPath.cs` | 89 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfkDlJLc_uVa1Pk9` | `csharpsquid:S6608` | `PasswordChangeProvider.cs` | 837 | MINOR | Present | Yes (Use indexing [0] instead of First()) |
| `AaAQzfkDlJLc_uVa1Pk_` | `csharpsquid:S6618` | `PasswordChangeProvider.cs` | 900 | MINOR | Present | Optional (string.Create optimization) |
| `AaAQzfkDlJLc_uVa1PlB` | `csharpsquid:S6608` | `PasswordChangeProvider.cs` | 1027 | MINOR | Present | Yes (Use indexing [0] instead of First()) |
| `AaAQzfkDlJLc_uVa1PlC` | `csharpsquid:S6618` | `PasswordChangeProvider.cs` | 1044 | MINOR | Present | Optional (string.Create optimization) |
| `AaAQzfXolJLc_uVa1Pjw` | `powershelldre:S8621` | `restart-passcore.ps1` | 100 | MINOR | Present | Yes (Fix PowerShell pipeline indentation) |
| `AaAQzfXdlJLc_uVa1Pju` | `shelldre:S1192` | `seedusers.sh` | 67 | MINOR | Present | Yes (Define variable for ou=groups) |
| `AaAQzfinlJLc_uVa1Pkm` | `external_roslyn:IDE0022` | `DomainPasswordPolicy.cs` | 53 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfWFlJLc_uVa1Pjb` | `external_roslyn:SYSLIB1045` | `LoggingConventionAuditTests.cs` | 40 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfWFlJLc_uVa1Pja` | `external_roslyn:SYSLIB1045` | `LoggingConventionAuditTests.cs` | 44 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfWFlJLc_uVa1Pje` | `external_roslyn:SYSLIB1045` | `LoggingConventionAuditTests.cs` | 287 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfWFlJLc_uVa1Pjf` | `external_roslyn:SYSLIB1045` | `LoggingConventionAuditTests.cs` | 291 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfk1lJLc_uVa1PlX` | `csharpsquid:S6618` | `LdapPasswordChangeProvider.cs` | 351 | MINOR | Present | Optional (string.Create optimization) |
| `AaAQzfk1lJLc_uVa1PlZ` | `csharpsquid:S2589` | `LdapPasswordChangeProvider.cs` | 386 | MAJOR | Present | Yes (Remove unnecessary null check) |
| `AaAQzfk1lJLc_uVa1PlY` | `csharpsquid:S6618` | `LdapPasswordChangeProvider.cs` | 387 | MINOR | Present | Optional (string.Create optimization) |
| `AaAQzfRAlJLc_uVa1PjU` | `external_roslyn:xUnit2031` | `LdapSearchFilterEscapingTests.cs` | 51 | MAJOR | Present | Yes (Use Assert.Single overload) |
| `AaAQzfRAlJLc_uVa1PjV` | `external_roslyn:xUnit2031` | `LdapSearchFilterEscapingTests.cs` | 78 | MAJOR | Present | Yes (Use Assert.Single overload) |
| `AaAQzfRAlJLc_uVa1PjW` | `external_roslyn:xUnit2031` | `LdapSearchFilterEscapingTests.cs` | 129 | MAJOR | Present | Yes (Use Assert.Single overload) |
| `AaAQzfkDlJLc_uVa1PlF` | `external_roslyn:CA1508` | `PasswordChangeProvider.cs` | 412 | MAJOR | Present | Yes (Refactor condition always null) |
| `AaAQzfk1lJLc_uVa1Pla` | `csharpsquid:S2589` | `LdapPasswordChangeProvider.cs` | 373 | MAJOR | Present | Yes (Remove unnecessary null check) |
| `AaAQzfUulJLc_uVa1PjX` | `external_roslyn:xUnit2031` | `GroupMembershipUndeterminedTests.cs` | 135 | MAJOR | Present | Yes (Use Assert.Single overload) |
| `AaAQzfXGlJLc_uVa1Pjn` | `external_roslyn:CA2249` | `AdProviderDirectoryWriteAuditTests.cs` | 212 | INFO | Present | Yes (Use string.Contains) |
| `AaAQzfXGlJLc_uVa1Pjo` | `external_roslyn:SYSLIB1045` | `AdProviderDirectoryWriteAuditTests.cs` | 266 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfkDlJLc_uVa1PlG` | `external_roslyn:CA1031` | `PasswordChangeProvider.cs` | 406 | MAJOR | Present | No (Catching Exception is required for fallback) |
| `AaAQzfiPlJLc_uVa1Pkb` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 209 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiPlJLc_uVa1Pkd` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 235 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiPlJLc_uVa1Pke` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 319 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiPlJLc_uVa1Pkg` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 352 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfk1lJLc_uVa1Plj` | `external_roslyn:IDE0022` | `LdapPasswordChangeProvider.cs` | 1402 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfk1lJLc_uVa1Plk` | `external_roslyn:IDE0022` | `LdapPasswordChangeProvider.cs` | 1405 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfk1lJLc_uVa1Pll` | `external_roslyn:IDE0022` | `LdapPasswordChangeProvider.cs` | 1411 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjzlJLc_uVa1Pk6` | `external_roslyn:IDE0022` | `AdministrativeReset.cs` | 64 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiPlJLc_uVa1Pkh` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 422 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfk1lJLc_uVa1Plb` | `csharpsquid:S3776` | `LdapPasswordChangeProvider.cs` | 1125 | CRITICAL | Present | Yes (Reduce complexity from 17 to <= 15) |
| `AaAQzfk1lJLc_uVa1Pli` | `external_roslyn:IDE0057` | `LdapPasswordChangeProvider.cs` | 1185 | INFO | Present | Yes (Simplify range slice syntax) |
| `AaAQzfU5lJLc_uVa1PjY` | `csharpsquid:S2699` | `LdapSecurityDescriptorTests.cs` | 123 | BLOCKER | Present | Yes (Add assertion to unit test) |
| `AaAQzfiPlJLc_uVa1Pki` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 425 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiPlJLc_uVa1Pkj` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 430 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiblJLc_uVa1Pkk` | `external_roslyn:IDE0022` | `PasswordChangeProviderBase.cs` | 146 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfdtlJLc_uVa1PkQ` | `external_roslyn:IDE0022` | `PwnedPasswordPolicy.cs` | 59 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiPlJLc_uVa1Pka` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 180 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiPlJLc_uVa1Pkc` | `external_roslyn:IDE0022` | `DirectoryErrorTranslator.cs` | 224 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjSlJLc_uVa1Pky` | `external_roslyn:IDE0022` | `Win32ErrorCode.cs` | 135 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjSlJLc_uVa1Pkz` | `external_roslyn:IDE0022` | `Win32ErrorCode.cs` | 142 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfjSlJLc_uVa1Pk0` | `external_roslyn:IDE0022` | `Win32ErrorCode.cs` | 149 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfk1lJLc_uVa1Ple` | `csharpsquid:S6444` | `LdapPasswordChangeProvider.cs` | 52 | MINOR | Present | Yes (Pass match timeout to Regex) |
| `AaAQzfk1lJLc_uVa1Plg` | `external_roslyn:SYSLIB1045` | `LdapPasswordChangeProvider.cs` | 52 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfk1lJLc_uVa1Pld` | `csharpsquid:S6444` | `LdapPasswordChangeProvider.cs` | 58 | MINOR | Present | Yes (Pass match timeout to Regex) |
| `AaAQzfk1lJLc_uVa1Plf` | `external_roslyn:SYSLIB1045` | `LdapPasswordChangeProvider.cs` | 58 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfk1lJLc_uVa1Plc` | `csharpsquid:S6444` | `LdapPasswordChangeProvider.cs` | 62 | MINOR | Present | Yes (Pass match timeout to Regex) |
| `AaAQzfk1lJLc_uVa1Plh` | `external_roslyn:SYSLIB1045` | `LdapPasswordChangeProvider.cs` | 62 | INFO | Present | Yes (Use GeneratedRegexAttribute) |
| `AaAQzfk1lJLc_uVa1PlT` | `csharpsquid:S127` | `LdapPasswordChangeProvider.cs` | 673 | MAJOR | Present | Yes (Refactor loop index mutation) |
| `AaAQzfk1lJLc_uVa1PlW` | `csharpsquid:S127` | `LdapPasswordChangeProvider.cs` | 731 | MAJOR | Present | Yes (Refactor loop index mutation) |
| `AaAQzflZlJLc_uVa1Plo` | `githubactions:S6505` | `.github/workflows/ci-testing.yml` | 116 | MAJOR | Present | Yes (Avoid unverified npx invocation) |
| `AaAQzflZlJLc_uVa1Plp` | `githubactions:S8543` | `.github/workflows/ci-testing.yml` | 116 | MAJOR | Present | Yes (Pin package versions) |
| `AaAQzfbLlJLc_uVa1Pj_` | `typescript:S6759` | `ChangePasswordForm.tsx` | 43 | MINOR | Present | Yes (Mark props as readonly) |
| `AaAQzfZllJLc_uVa1Pj4` | `typescript:S2933` | `GoogleReCaptcha.tsx` | 31 | MAJOR | Present | Yes (Mark member as readonly) |
| `AaAQzfYxlJLc_uVa1Pj0` | `typescript:S8786` | `HtmlStringUtils.tsx` | 34 | MAJOR | Present | Yes (Simplify regex to prevent backtracking) |
| `AaAQzfbglJLc_uVa1PkC` | `typescript:S6754` | `ChangePassword.tsx` | 21 | MINOR | Present | Yes (Destructure useState call) |
| `AaAQzfbglJLc_uVa1PkD` | `typescript:S6754` | `ChangePassword.tsx` | 23 | MINOR | Present | Yes (Destructure useState call) |
| `AaAQzfbqlJLc_uVa1PkE` | `typescript:S6754` | `useEffectWithLoading.ts` | 7 | MINOR | Present | Yes (Destructure useState call) |
| `AaAQzfZblJLc_uVa1Pj3` | `typescript:S6582` | `AppSettings.ts` | 6 | MINOR | Present | Yes (Use optional chaining) |
| `AaAQzfYxlJLc_uVa1Pjz` | `typescript:S8786` | `HtmlStringUtils.tsx` | 19 | MAJOR | Present | Yes (Simplify regex) |
| `AaAQzfkjlJLc_uVa1PlQ` | `external_roslyn:CA1859` | `DebugPasswordChangeProvider.cs` | 28 | INFO | Present | Optional (Change dictionary type) |
| `AaAQzfdilJLc_uVa1PkL` | `csharpsquid:S1118` | `Program.cs` | 95 | MAJOR | Present | No (Required for WebApplicationFactory in tests) |
| `AaAQzfWrlJLc_uVa1Pjk` | `external_roslyn:CA1861` | `PasswordChangeProviderBaseTests.cs` | 124 | INFO | Present | Yes (Use static readonly array) |
| `AaAQzfiDlJLc_uVa1PkW` | `external_roslyn:IDE0022` | `PasswordChangeResult.cs` | 18 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiDlJLc_uVa1PkX` | `external_roslyn:IDE0022` | `PasswordChangeResult.cs` | 21 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfiDlJLc_uVa1PkZ` | `external_roslyn:IDE0022` | `PasswordChangeResult.cs` | 24 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfdtlJLc_uVa1PkP` | `csharpsquid:S1125` | `PwnedPasswordPolicy.cs` | 29 | MINOR | Present | Yes (Remove unnecessary boolean literal) |
| `AaAQzfiDlJLc_uVa1PkY` | `external_roslyn:IDE0022` | `PasswordChangeResult.cs` | 27 | INFO | Present | No (Expression body is preferred) |
| `AaAQzflZlJLc_uVa1Plq` | `githubactions:S6505` | `.github/workflows/ci-testing.yml` | 148 | MAJOR | Present | Yes (Avoid unverified npx invocation) |
| `AaAQzflZlJLc_uVa1Plr` | `githubactions:S8543` | `.github/workflows/ci-testing.yml` | 148 | MAJOR | Present | Yes (Pin package versions) |
| `AaAQzfnalJLc_uVa1Pl2` | `docker:S7018` | `Dockerfile` | 10 | MINOR | Present | Yes (Sort package names alphanumerically) |
| `AaAQzfnalJLc_uVa1Pl3` | `docker:S8482` | `Dockerfile` | 16 | BLOCKER | Present | Optional (Script download from official MS domain) |
| `AaAQzfnalJLc_uVa1Pl4` | `docker:S6506` | `Dockerfile` | 16 | MAJOR | Present | Yes (Enforce HTTPS) |
| `AaAQzfnalJLc_uVa1Pl5` | `docker:S8482` | `Dockerfile` | 26 | BLOCKER | Present | Optional (Script download from official MS domain) |
| `AaAQzfnalJLc_uVa1Pl6` | `docker:S6471` | `Dockerfile` | 38 | MINOR | Present | Contextual (Non-root user configuration) |
| `AaAQzfbWlJLc_uVa1PkA` | `typescript:S6759` | `PasswordStrengthBar.tsx` | 49 | MINOR | Present | Yes (Mark props as readonly) |
| `AaAQzfbAlJLc_uVa1Pj-` | `typescript:S6759` | `ReCaptcha.tsx` | 11 | MINOR | Present | Yes (Mark props as readonly) |
| `AaAQzfcMlJLc_uVa1PkH` | `typescript:S6759` | `ChangePasswordDialog.tsx` | 15 | MINOR | Present | Yes (Mark props as readonly) |
| `AaAQzfcAlJLc_uVa1PkG` | `typescript:S6759` | `GlobalContextProvider.tsx` | 10 | MINOR | Present | Yes (Mark props as readonly) |
| `AaAQzfb2lJLc_uVa1PkF` | `typescript:S6759` | `SnackbarContextProvider.tsx` | 17 | MINOR | Present | Yes (Mark props as readonly) |
| `AaAQzfdilJLc_uVa1PkM` | `csharpsquid:S1075` | `Program.cs` | 31 | MINOR | Present | No (Standard default public API base URL) |
| `AaAQzfdilJLc_uVa1PkN` | `csharpsquid:S1075` | `Program.cs` | 36 | MINOR | Present | No (Standard default public API base URL) |
| `AaAQzfdilJLc_uVa1PkO` | `csharpsquid:S6966` | `Program.cs` | 90 | MAJOR | Present | Yes (Await app.RunAsync()) |
| `AaAQzfX9lJLc_uVa1Pjy` | `typescript:S3358` | `FetchRequest.ts` | 19 | MAJOR | Present | Yes (Extract nested ternary) |
| `AaAQzfYxlJLc_uVa1Pj1` | `typescript:S6594` | `HtmlStringUtils.tsx` | 38 | MINOR | Present | Yes (Use RegExp.exec()) |
| `AaAQzfYxlJLc_uVa1Pj2` | `typescript:S8786` | `HtmlStringUtils.tsx` | 38 | MAJOR | Present | Yes (Simplify regex) |
| `AaAQzfcXlJLc_uVa1PkI` | `javascript:S7772` | `version-script.mjs` | 1 | MINOR | Present | Yes (Use node:fs import) |
| `AaAQzfnRlJLc_uVa1Pl1` | `powershelldre:S8642` | `Installer.ps1` | 42 | MAJOR | Present | Yes (Use PascalCase cmdlet New-Object) |
| `AaAQzfeMlJLc_uVa1PkV` | `external_roslyn:IDE0022` | `ApiErrorException.cs` | 52 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfkOlJLc_uVa1PlM` | `external_roslyn:CA1052` | `NativeMethods.cs` | 8 | MAJOR | Present | Yes (Mark class as static) |
| `AaAQzfeMlJLc_uVa1PkU` | `external_roslyn:IDE0021` | `ApiErrorException.cs` | 34 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfkXlJLc_uVa1PlP` | `external_roslyn:CA1819` | `PasswordChangeOptions.cs` | 48 | INFO | Present | No (Required for ASP.NET Core array configuration) |
| `AaAQzfk_lJLc_uVa1Plm` | `external_roslyn:CA1819` | `LdapPasswordChangeOptions.cs` | 19 | INFO | Present | No (Required for ASP.NET Core array configuration) |
| `AaAQzfnRlJLc_uVa1Pl0` | `powershelldre:S8642` | `Installer.ps1` | 32 | MAJOR | Present | Yes (Use PascalCase Get-WmiObject) |
| `AaAQzfnRlJLc_uVa1Plz` | `powershelldre:S8638` | `Installer.ps1` | 32 | MAJOR | Present | Yes (Replace Get-WmiObject with Get-CimInstance) |
| `AaAQzfZllJLc_uVa1Pj8` | `typescript:S6582` | `GoogleReCaptcha.tsx` | 131 | MINOR | Present | Yes (Use optional chaining) |
| `AaAQzfkDlJLc_uVa1Pk8` | `csharpsquid:S2325` | `PasswordChangeProvider.cs` | 476 | MINOR | Present | Yes (Make method static) |
| `AaAQzfkDlJLc_uVa1PlL` | `external_roslyn:CA1822` | `PasswordChangeProvider.cs` | 476 | MAJOR | Present | Yes (Make method static) |
| `AaAQzfZllJLc_uVa1Pj5` | `typescript:S7741` | `GoogleReCaptcha.tsx` | 61 | MINOR | Present | Yes (Compare directly with undefined) |
| `AaAQzfZllJLc_uVa1Pj6` | `typescript:S6441` | `GoogleReCaptcha.tsx` | 79 | MAJOR | Present | Contextual (Imperative ref method) |
| `AaAQzfZllJLc_uVa1P7` | `typescript:S6441` | `GoogleReCaptcha.tsx` | 85 | MAJOR | Present | Contextual (Imperative ref method) |
| `AaAQzfchlJLc_uVa1PkJ` | `external_roslyn:IDE0022` | `HomeController.cs` | 16 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfeMlJLc_uVa1PkT` | `csharpsquid:S3427` | `ApiErrorException.cs` | 34 | BLOCKER | Present | Yes (Fix overlapping constructor default params) |
| `AaAQzfixlJLc_uVa1Pkn` | `external_roslyn:CA1819` | `IAppSettings.cs` | 86 | INFO | Present | No (Required for array configuration binding) |
| `AaAQzfkDlJLc_uVa1PlD` | `external_roslyn:CS1591` | `PasswordChangeProvider.cs` | 236 | MAJOR | Present | Yes (Add XML documentation comments) |
| `AaAQzfdXlJLc_uVa1PkK` | `external_roslyn:IDE0022` | `PasswordController.cs` | 65 | INFO | Present | No (Expression body is preferred) |
| `AaAQzfnQlJLc_uVa1Plv` | `powershelldre:S8642` | `Installer.ps1` | 18 | MAJOR | Present | Yes (Use PascalCase Where-Object) |
| `AaAQzfnRlJLc_uVa1Plw` | `powershelldre:S8642` | `Installer.ps1` | 18 | MAJOR | Present | Yes (Use lowercase -notlike operator) |
| `AaAQzfnRlJLc_uVa1Plx` | `powershelldre:S8642` | `Installer.ps1` | 18 | MAJOR | Present | Yes (Use lowercase -notlike operator) |
| `AaAQzflklJLc_uVa1Pls` | `powershelldre:S8622` | `IISSetup.ps1` | 35 | MINOR | Present | Yes (Use -not operator) |
| `AaAQzflklJLc_uVa1Plt` | `powershelldre:S8642` | `IISSetup.ps1` | 41 | MAJOR | Present | Yes (Use PascalCase parameter -Value) |
| `AaAQzflklJLc_uVa1Plu` | `powershelldre:S8622` | `IISSetup.ps1` | 63 | MINOR | Present | Yes (Use -not operator) |
| `AaAQzfnRlJLc_uVa1Ply` | `powershelldre:S8642` | `Installer.ps1` | 28 | MAJOR | Present | Yes (Use PascalCase parameter -Force) |
| `AaAQzfkOlJLc_uVa1PlN` | `external_roslyn:CA5392` | `NativeMethods.cs` | 42 | MAJOR | Present | Yes (Add DefaultDllImportSearchPaths) |
| `AaAQzfkOlJLc_uVa1PlO` | `external_roslyn:SYSLIB1054` | `NativeMethods.cs` | 42 | INFO | Present | Yes (Use LibraryImportAttribute) |

---
