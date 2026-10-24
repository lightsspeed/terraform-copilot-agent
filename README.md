# Terraform Copilot Agent

An AI-powered Terraform assistant designed for DevOps engineers to safely understand, generate, inspect, and validate Terraform configurations using deterministic tools rather than trusting LLMs to run arbitrary shell commands.

---

## 1. Project Objective

LLMs are prone to hallucinating command-line flags, running unvetted shell scripts, or attempting state-altering commands without human oversight. **Terraform Copilot Agent** acts as an intelligent pair programmer for infrastructure as code by enforcing a strict security boundary:

- Natural language queries and code explanations are handled by the LLM.
- All file inspections, formatting, and syntax validations are executed through deterministic, allowlisted tools.
- Infrastructure state cannot be mutated in V1 (no `apply`, `destroy`, `import`, or state manipulation).
- Tools are structured to easily expose capabilities to IDEs and agents via the Model Context Protocol (MCP).

---

## 2. Architecture Overview

The system is separated into decoupled, single-responsibility layers:

```text
+--------------------------------------------------------------+
|                    Client / Interface Layer                  |
|                 (CLI / Future MCP Clients)                   |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                   Agent Orchestration Layer                  |
|          Bounded iteration, history tracking, tool router    |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                     Security & Policy Layer                  |
|     Path sandboxing, command allowlist, secret redaction     |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                  Terraform Tool Execution                    |
|   Deterministic subprocess runner (shell=False, timeouts)    |
|   Workspace file manager (safe read/write/inspect)           |
+--------------------------------------------------------------+
```

### Component Boundaries
- **Security & Policy Layer**: Enforces containment within the workspace directory, blocks directory traversal (`../`) and external symlinks, and validates commands against an explicit allowlist.
- **Terraform Execution Layer**: Invokes the local Terraform CLI via argument lists (`subprocess.run(..., shell=False)`), enforces timeouts, and parses structured diagnostics (`terraform validate -json`).
- **File Management Layer**: Confines file reading and writing strictly to the isolated project workspace, preventing sensitive files (`.tfstate`, `.tfplan`, credentials) from being accessed.
- **LLM Provider Layer**: Minimal, swappable provider interface (`LLMProvider`) driven initially by a deterministic `MockLLMProvider` for tests and reproducible agent flows.
- **MCP Adapter Layer**: Exposes internal validated tool functions directly through the official Model Context Protocol Python SDK.

---

## 3. Prerequisites

- **Python**: `>= 3.12`
- **uv**: `>= 0.12` ([uv installation guide](https://github.com/astral-sh/uv))
- **Terraform CLI**: `>= 1.5` installed and available on `PATH`
- **Git**: For version control and trunk-based development

---

## 4. Security Boundaries & Threat Model

| Threat / Risk | Mitigation Strategy | Boundary / Known Limitation |
| :--- | :--- | :--- |
| **Arbitrary Shell Execution** | Subprocess invocation strictly uses fixed argument lists with `shell=False`. No raw shell strings are ever passed to the OS. | Mitigates LLM command injection. Does not sandbox host binary execution. |
| **State Mutation & Drift** | Strict command allowlist: only `fmt -check`, `init -backend=false`, and `validate -json` are permitted. State-mutating commands (`apply`, `destroy`, `import`, `state`) are blocked. | V1 strictly provides read/format/validate capabilities. |
| **Path Traversal & Symlink Escape** | Strict path resolution (`Path.resolve()`) verifying that target paths remain inside the designated workspace. Symlinks pointing outside are rejected. | Prevents reading or writing arbitrary host files. |
| **Sensitive File & Secret Exfiltration** | Denylist patterns (`*.tfstate*`, `*.tfplan`, `*.pem`, `*.key`, `.env*`). Diagnostics and outputs are scrubbed through regex-based secret redactors. | Heuristic regex scrubbing reduces exposure but is not an absolute DLP guarantee. |
| **Untrusted Terraform & Provider Execution** | Subprocess runs with controlled environment variables (`TF_INPUT=0`, `TF_IN_AUTOMATION=1`) and execution timeouts (default 30s). | **Critical Limitation**: `terraform init` and provider plugins execute native binaries. `-backend=false` disables remote state, but does not provide OS-level container isolation. Running untrusted third-party providers on bare host is a privilege boundary limitation in V1. Full sandbox isolation (e.g. Docker/gVisor) is deferred to future milestones. |
| **Infinite Agent Retries** | Orchestrator enforces a hard limit on correction iterations (`max_iterations = 3`). | Bounded self-correction prevents endless retry loops on broken configurations. |

---

---

## 5. Security Architecture & Interfaces

The Security and Policy Layer (`terraform_copilot_agent.security`) enforces strict deterministic controls before any file is read/written or any subprocess is spawned:

### 1. `PathValidator`
- **Containment**: Resolves candidate paths against a designated canonical `workspace_root` directory.
- **Traversal Protection**: Rejects parent directory traversal (`../`) and nested traversal attempts (`PathTraversalError`).
- **Symlink Escapes**: Detects symlink chains pointing outside the workspace boundary (`SymlinkEscapeError`).
- **Prospective Destinations**: Safely validates destination paths that do not yet exist on disk (e.g., when generating new configuration files), ensuring their prospective paths remain strictly contained.

### 2. `SafetyPolicy` & `CommandSpec`
- **Closed Allowlist**: Only three deterministic Terraform subcommands are permitted in V1:
  - `terraform fmt -check` (optionally targeting a safe relative file within the workspace)
  - `terraform init -backend=false`
  - `terraform validate -json`
- **Shell Injection Immunity**: Scans arguments and flags for shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `\n`, etc.) and rejects arbitrary executable names.
- **State Mutation Block**: Explicitly rejects `apply`, `destroy`, `import`, `state`, `taint`, `untaint`, `refresh`, and other mutating commands (`ForbiddenCommandError`).
- **Subprocess Argument Lists**: Generates typed argument lists (`list[str]`) for `subprocess.run(..., shell=False)`.

### 3. Sensitive File Policy
- **Denylist Blocking**: Blocks read and write access to files matching sensitive patterns (`SensitiveFileError`):
  - State files: `*.tfstate`, `*.tfstate.*`, `*.tfstate.backup` (case-insensitive)
  - Plan files: `*.tfplan`
  - Secret & environment files: `.env`, `.env.*`
  - Private keys: `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.pkcs12`, `*.pfx`
  - Credentials: `*credentials*`, `*secret*`

### 4. `Redactor`
- **Credential Scrubbing**: Heuristically masks common sensitive tokens in command outputs, diagnostics, and configurations:
  - AWS Access Key IDs (`[REDACTED_AWS_KEY]`)
  - AWS Secret Access Keys (`[REDACTED_AWS_SECRET]`)
  - PEM / OpenSSH private key blocks (`[REDACTED_PRIVATE_KEY]`)
  - HTTP Bearer authorization tokens (`[REDACTED_BEARER_TOKEN]`)
  - Password, secret, and API token assignments (`[REDACTED_CREDENTIAL]`)
- **Diagnostic Preservation**: Preserves normal Terraform error diagnostics, syntax messages, HCL definitions, and line numbers.
- **Security Limitation**: Regex scrubbing is a best-effort defense-in-depth mitigation and does not substitute for a complete Data Loss Prevention (DLP) system.

---

## 6. Development Workflow & Trunk-Based Development

This project strictly follows **Trunk-Based Development**:

- **Trunk (`main`)**: The single source of truth. Must always remain in a working, tested state.
- **Short-Lived Feature Branches**: Branch off `main` for focused changes:
  - `feat/security-policy`
  - `feat/terraform-runner`
  - `feat/agent-orchestrator`
  - `feat/mcp-server`
  - `fix/path-traversal`
  - `test/terraform-validation`
- **Conventional Commits**: Small, meaningful commits:
  - `feat: add Terraform command allowlist`
  - `fix: reject workspace path traversal`
  - `test: cover Terraform runner timeouts`
  - `docs: document MCP architecture`

### Local Setup & Verification

All commands use Bash syntax:

```bash
# 1. Clone the repository
git clone https://github.com/lightsspeed/terraform-copilot-agent.git
cd terraform-copilot-agent

# 2. Synchronize virtual environment with uv
uv sync

# 3. Copy example environment variables
cp .env.example .env

# 4. Run tests
uv run pytest -v
```

---

## 7. Project Roadmap

- [x] **Milestone 1**: Project Scaffolding, Trunk-Based Git Setup, CI Foundation, and Architecture Documentation.
- [x] **Milestone 2**: Security & Policy Layer (Path containment, command allowlist, secret redaction, unit tests).
- [ ] **Milestone 3**: Deterministic Terraform Runner & Safe File Manager (Subprocess execution, timeouts, diagnostics parsing, integration tests).
- [ ] **Milestone 4**: Mock LLM Provider, Execution History, & Bounded Agent Orchestration.
- [ ] **Milestone 5**: Official MCP Server Adapter & Tool Dispatch.
- [ ] **Milestone 6**: CLI Interface, Full End-to-End Verification, and Milestone Review.
