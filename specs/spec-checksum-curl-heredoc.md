# Checksum, curl, and quoted-heredoc command handling

### 1. Checksum defaults

- [x] Allow direct `shasum` reads without weakening path protections.

#### Why
Safe verification commands currently stop otherwise-approved Git inspection compounds.

#### How
Add the command family, parse algorithm option values separately from file operands, and keep indirect checksum-manifest reads gated.

#### Where
`src/config/schema.ts`, `src/policy/commands.ts`, regression tests.

#### Acceptance criteria
- Direct SHA-256 verification and Git/checksum compounds pass built-in policy.
- Credential and outside-project reads remain blocked.
- Manifest-driven reads do not gain implicit authorization.

### 2. Curl path handling and defaults

- [x] Parse curl file arguments before allowing the command family by default.

#### Why
Downloads and uploads must not bypass filesystem policy through curl-specific options.

#### How
Treat curl as an ordinary allowed command; network filtering belongs to the user's separate extension. Recognize explicit output/upload/data/form/header/cookie/TLS file arguments, attached options and local file URLs. Gate opaque configurations, remote-derived output names and unresolved file operands. Do not require `-q` or add network/domain restrictions. Implicit curl configuration remains outside static command inspection.

#### Where
`src/policy/curl.ts`, `src/policy/commands.ts`, `src/config/schema.ts`, regression tests, policy documentation.

#### Acceptance criteria
- Ordinary HTTP(S) HEAD requests and explicit project downloads pass without additional network approval.
- Upload/read and download/write paths participate in credential, symlink, outside-project and read-only checks.
- Recognized indirect or unresolved file access does not silently inherit `curl *` permission.
- Denied segments still block compounds.

### 3. Quoted heredoc parsing

- [x] Distinguish literal stdin program/data text from shell command syntax.

#### Why
A Node diagnostic heredoc was hard-denied because JavaScript syntax was interpreted as shell executables.

#### How
Parse quoted heredoc boundaries before shell tokenization and substitution scanning; inspect supported interpreter stdin as inline code and shell stdin as shell code. Keep trailing commands and outer redirections. Reject unsupported/ambiguous heredoc routing rather than silently skipping it.

#### Where
`src/policy/heredocs.ts`, `src/policy/commands.ts`, regression tests, policy documentation.

#### Acceptance criteria
- Literal JavaScript arrays, imports, backticks and sample command strings no longer become executable shell segments.
- Interpreter credential/environment/cloud/destructive guards still apply.
- Shell heredoc commands and commands after delimiters remain guarded.
- Multiple documents, tab stripping, malformed delimiters and ambiguous/unquoted forms are tested.

### 4. Sonar maintainability cleanup

- [x] Resolve the seven active Sonar findings without changing command-policy behavior.

#### Why
Fresh analysis reports nested ternaries, excessive function complexity and two syntax/readability findings in the new classifiers.

#### How
Follow Sonar guidance: separate nested decisions, extract top-level parsing helpers, simplify the digit character class and use `String.raw` for literal backslashes. Run regression tests and rescan.

#### Where
`src/policy/commands.ts`, `src/policy/curl.ts`, `src/policy/heredocs.ts`, focused regression tests.

#### Acceptance criteria
- Existing command authorization and parsing regression tests pass.
- A fresh processed Sonar analysis reports no active issues and a passing quality gate.

## Validation

- `npm run validate`: passed (321 tests, typecheck, script syntax and package checks).
- `npm run format:check`: passed.
- `git diff --check`: passed.
- Final processed Sonar scan: quality gate OK, zero active issues, zero bugs/vulnerabilities/security hotspots. Task: `AaBwppA2R348sxUkODf2`.
- Regression cases cover all three original command compounds with display wrapping removed; no sample download, upload or diagnostic command is executed by the tests.
