# Strict local bridge contract

Strict mode is the default. Starting a session requires the operator to set
`CLAUDE_CODE_MCP_ALLOWED_PROJECT_ROOTS` to a nonempty JSON array of absolute
project directories. The filesystem root and protected storage path components
(`.claude`, `.codex`, `.ssh`, `.aws`, `.env*`, `.credentials.json`) are rejected.
Do not allow a home directory or a directory containing credentials.

Caller cwd and additional directories are checked against canonical roots using
real paths of existing ancestors. Dangling and external symlinks are rejected.
Only explicitly enabled `Read`, `Write` and `Edit` built-ins are supported;
the default tool set is empty. Shell commands, recursive search, subagents,
network tools and caller-provided MCP servers are unavailable in strict mode.
A pre-tool hook checks the file path and requires an explicit permission
decision even for reads. The callback queues decisions rather than preapproving
allowedTools, and permission responses are checked again after edits to input.
Existing cancellation, timeout and queue capacity limits remain effective.

Caller executable, environment, settings, subagent, sandbox and tool-config
overrides are rejected. The pinned SDK-bundled executable is used without PATH
discovery. Settings sources are empty and MCP configuration is explicitly empty
and strict. Debug logging, disk persistence/checkpoints and disk resume are
disabled. No HMAC secret is needed. In-memory session lifecycle remains managed
by the bridge; the existing reply API's non-persistent-session restriction still
applies. Do not expect durable conversations from this strict contract.

The child receives only LANG, LC_ALL, TZ, SYSTEMROOT and WINDIR if present.
HOME, PATH, credentials, proxies and Node injection variables are not inherited.
Existing authentication mechanisms must be reviewed separately before enabling
real queries. This change does not create credentials, change HOME, isolate
Claude's credential storage or prevent the SDK/CLI from performing its own
authentication/network behavior. No real CLI/auth integration was tested.

Outgoing stdio messages (including tool results, structuredContent, resources
and logging notifications) and bridge console errors pass through bounded
redaction. Known key prefixes, Bearer tokens, labeled secrets and selected
structured keys are redacted. Raw child stderr is discarded in strict mode.
Unknown/unlabeled, encoded or split secrets cannot reliably be recognized.
The redactor does not scan process.env for secret values. Oversized text and
excessively nested values are replaced; output may therefore lose information.
Redaction is not permission enforcement or protection against arbitrary data
exfiltration by an authorized client. Prompts and tool inputs sent to Claude
are not redacted: users must not supply secrets they do not intend to send.

These checks constrain bridge parameters and supported tools, **not the OS**.
Symlink replacement between validation and file access (TOCTOU), hard links,
credential files under unexpected names and SDK internal filesystem/network
behavior require a separately enforced OS/container filesystem and egress
boundary. Do not enable the bridge against hostile mutable directories or
credential-bearing projects based only on these checks. No claim of a complete
filesystem sandbox or guaranteed token secrecy is made.

`CLAUDE_CODE_MCP_SECURITY_MODE=legacy` explicitly restores historical caller
options and permission preapproval behavior for migration. It is unsafe for
untrusted clients. Even legacy mode receives the minimal inherited environment
(with explicit caller env overrides) and outgoing redaction. Existing regression
tests select this legacy contract explicitly; separate security tests exercise
strict production defaults, malicious parameters, artificial secret canaries,
symlink escapes, changed permission inputs and cancellation without real auth.

The lockfile was refreshed using npm's official advisory-driven remediation with
lifecycle scripts disabled. The three direct runtime SDK/Zod versions remain
unchanged. Development tool updates and their dependency changes address the
reported advisories; no audit findings were suppressed. Use `npm ci
--ignore-scripts` for reproducible installation, then run separately reviewed
build steps. No broad npm latest update or unreviewed fork is required.
