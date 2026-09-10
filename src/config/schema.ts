import { BUILT_IN_GUARDED_TOOLS, GUARDED_TOOL_NAMES, POLICY_VERSION, type GuardedToolContract } from "../constants.ts";
import { type ApprovalMode, isApprovalMode } from "./approval-mode.ts";
import {
  PATH_POLICY_ACTIONS,
  type PathPolicyAction,
  type PolicyAction,
  type PolicyDiagnostic,
  type RuleSource,
  type RuleSourceKind,
  isPolicyAction,
} from "../policy/action.ts";

const OS_TEMP_DIRECTORY = ["/", "tmp"].join("");
const OS_PRIVATE_TEMP_DIRECTORY = ["/private/", "tmp"].join("");
const OS_VAR_TEMP_DIRECTORY = ["/var/", "tmp"].join("");
const OS_PRIVATE_VAR_TEMP_DIRECTORY = ["/private/var/", "tmp"].join("");

export const PATH_RULE_SECTIONS = [
  "allowPaths",
  "denyPaths",
  "zeroAccessPaths",
  "readOnlyPaths",
  "noDeletePaths",
  "protectedCredentialPaths",
] as const;
export type PathRuleSection = (typeof PATH_RULE_SECTIONS)[number];

export const COMMAND_RULE_SECTIONS = ["allowCommands", "denyCommands", "dangerousCommands"] as const;
export type CommandRuleSection = (typeof COMMAND_RULE_SECTIONS)[number];

export const POLICY_CONFIG_SECTIONS = [...PATH_RULE_SECTIONS, ...COMMAND_RULE_SECTIONS] as const;
export type PolicyConfigSection = (typeof POLICY_CONFIG_SECTIONS)[number];

const PATH_RULE_SECTION_SET: ReadonlySet<string> = new Set(PATH_RULE_SECTIONS);
const COMMAND_RULE_SECTION_SET: ReadonlySet<string> = new Set(COMMAND_RULE_SECTIONS);
const POLICY_CONFIG_SECTION_SET: ReadonlySet<string> = new Set(POLICY_CONFIG_SECTIONS);

export interface GuardMeRule {
  readonly pattern: string;
  readonly actions?: readonly PolicyAction[];
  readonly reason?: string;
}

export interface GuardMePathRule extends GuardMeRule {
  readonly actions?: readonly PathPolicyAction[];
}

export interface GuardMePolicyConfig {
  readonly version: number;
  readonly approvalMode?: ApprovalMode;
  readonly guardedTools?: Readonly<Record<string, GuardedToolContract>>;
  readonly allowPaths: readonly GuardMePathRule[];
  readonly denyPaths: readonly GuardMePathRule[];
  readonly zeroAccessPaths: readonly GuardMePathRule[];
  readonly readOnlyPaths: readonly GuardMePathRule[];
  readonly noDeletePaths: readonly GuardMePathRule[];
  readonly allowCommands: readonly GuardMeRule[];
  readonly denyCommands: readonly GuardMeRule[];
  readonly dangerousCommands: readonly GuardMeRule[];
  readonly protectedCredentialPaths: readonly GuardMePathRule[];
}

export interface ConfigValidationResult {
  readonly config: GuardMePolicyConfig;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

export interface ParsePolicyYamlResult {
  readonly data: Record<string, unknown>;
  readonly diagnostics: readonly PolicyDiagnostic[];
}

const ALL_PATH_ACTIONS: readonly PathPolicyAction[] = PATH_POLICY_ACTIONS;

export function createEmptyPolicyConfig(version = POLICY_VERSION): GuardMePolicyConfig {
  return {
    version,
    guardedTools: {},
    allowPaths: [],
    denyPaths: [],
    zeroAccessPaths: [],
    readOnlyPaths: [],
    noDeletePaths: [],
    allowCommands: [],
    denyCommands: [],
    dangerousCommands: [],
    protectedCredentialPaths: [],
  };
}

export function createBuiltInDefaultPolicy(): GuardMePolicyConfig {
  return {
    ...createEmptyPolicyConfig(POLICY_VERSION),
    approvalMode: "auto",
    allowPaths: [
      {
        pattern: "/dev/null",
        actions: ["write"],
        reason: "Allow shell stderr/stdout redirection sink.",
      },
      {
        pattern: "**/.pi/skills",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "**/.pi/skills/**",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "**/.pi/skill",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "**/.pi/skill/**",
        actions: ["read", "list"],
        reason: "Pi skill files may be loaded from sibling repositories or global skill directories.",
      },
      {
        pattern: "**/node_modules/@earendil-works",
        actions: ["read", "list"],
        reason: "Allow discovery of all @earendil-works packages across installation locations.",
      },
      {
        pattern: "**/node_modules/@earendil-works/**",
        actions: ["read", "list"],
        reason: "Allow reading all @earendil-works package contents across installation locations.",
      },
      {
        pattern: "~/.agent-browser/**",
        actions: ["read", "list"],
        reason: "agent-browser writes screenshots and session state there; agents read screenshots back as images.",
      },
      {
        pattern: OS_TEMP_DIRECTORY,
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory root, so copying or listing into it works like its contents.",
      },
      {
        pattern: OS_PRIVATE_TEMP_DIRECTORY,
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory root, so copying or listing into it works like its contents.",
      },
      {
        pattern: OS_VAR_TEMP_DIRECTORY,
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory root, so copying or listing into it works like its contents.",
      },
      {
        pattern: OS_PRIVATE_VAR_TEMP_DIRECTORY,
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory root, so copying or listing into it works like its contents.",
      },
      {
        pattern: "/var/folders/*/*/T",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory root, so copying or listing into it works like its contents.",
      },
      {
        pattern: "/private/var/folders/*/*/T",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory root, so copying or listing into it works like its contents.",
      },
      {
        pattern: "/tmp/**",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory: scratch files, logs and downloads agents create while working. Credential-like names and .env files stay protected.",
      },
      {
        pattern: "/private/tmp/**",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory: scratch files, logs and downloads agents create while working. Credential-like names and .env files stay protected.",
      },
      {
        pattern: "/var/tmp/**",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory: scratch files, logs and downloads agents create while working. Credential-like names and .env files stay protected.",
      },
      {
        pattern: "/private/var/tmp/**",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory: scratch files, logs and downloads agents create while working. Credential-like names and .env files stay protected.",
      },
      {
        pattern: "/var/folders/*/*/T/**",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory: scratch files, logs and downloads agents create while working. Credential-like names and .env files stay protected.",
      },
      {
        pattern: "/private/var/folders/*/*/T/**",
        actions: ["read", "list", "write", "edit", "delete", "move", "rename"],
        reason: "Operating-system temp directory: scratch files, logs and downloads agents create while working. Credential-like names and .env files stay protected.",
      },
    ],
    allowCommands: [
      { pattern: "true", reason: "Allow no-op shell fallback in compound commands." },
      { pattern: "pwd *", reason: "Project working-directory discovery." },
      { pattern: "mkdir *", reason: "Project directory creation after path protections pass." },
      { pattern: "tree *", reason: "Project directory tree after path protections pass." },
      { pattern: "ls *", reason: "Project file listing after path protections pass." },
      { pattern: "cat *", reason: "Project file reads after path protections pass." },
      { pattern: "head *", reason: "Project file reads after path protections pass." },
      { pattern: "tail *", reason: "Project file reads after path protections pass." },
      { pattern: "wc *", reason: "Project file reads after path protections pass." },
      { pattern: "shasum *", reason: "Direct checksum reads after path protections pass." },
      { pattern: "curl *", reason: "Ordinary curl requests after explicit local file path protections pass; network policy is external." },
      { pattern: "grep *", reason: "Project search after path protections pass." },
      { pattern: "ggrep *", reason: "Project search after path protections pass." },
      { pattern: "find *", reason: "Project discovery after path protections pass." },
      { pattern: "rg *", reason: "Project discovery after path protections pass." },
      { pattern: "npm *", reason: "Common project npm command." },
      { pattern: "npx *", reason: "Common project npx command." },
      { pattern: "pnpm *", reason: "Common project pnpm command." },
      { pattern: "yarn *", reason: "Common project yarn command." },
      { pattern: "bun *", reason: "Common project bun command." },
      { pattern: "bunx *", reason: "Common project bunx command." },
      { pattern: "corepack *", reason: "Common project corepack command." },
      { pattern: "deno *", reason: "Common project deno command." },
      { pattern: "node *", reason: "Common project quick action command." },
      { pattern: "tsc *", reason: "Common project TypeScript compiler command." },
      { pattern: "tsx *", reason: "Common project tsx runner command." },
      { pattern: "ts-node *", reason: "Common project ts-node runner command." },
      { pattern: "eslint *", reason: "Common project eslint command." },
      { pattern: "prettier *", reason: "Common project prettier command." },
      { pattern: "vitest *", reason: "Common project vitest command." },
      { pattern: "jest *", reason: "Common project jest command." },
      { pattern: "git *", reason: "Common project git command." },
      { pattern: "jq *", reason: "Common project jq command." },
      { pattern: "yq *", reason: "Common project yq command." },
      { pattern: "fd *", reason: "Common project fd command." },
      { pattern: "sed *", reason: "Common project sed command." },
      { pattern: "awk *", reason: "Common project awk command after path protections pass." },
      { pattern: "cut *", reason: "Common project cut command." },
      { pattern: "tr *", reason: "Common project tr command." },
      { pattern: "uniq *", reason: "Common project uniq command." },
      { pattern: "sort *", reason: "Common project sort command." },
      { pattern: "nl *", reason: "Common project nl command." },
      { pattern: "diff *", reason: "Common project diff command." },
      { pattern: "xargs *", reason: "Wrapped commands are still checked segment by segment." },
      { pattern: "tee *", reason: "Common project tee command after path protections pass." },
      { pattern: "touch *", reason: "Common project touch command after path protections pass." },
      { pattern: "stat *", reason: "Common project stat command." },
      { pattern: "file *", reason: "Common project file command." },
      { pattern: "du *", reason: "Common project du command." },
      { pattern: "basename *", reason: "Common project basename command." },
      { pattern: "dirname *", reason: "Common project dirname command." },
      { pattern: "realpath *", reason: "Common project realpath command." },
      { pattern: "readlink *", reason: "Common project readlink command." },
      { pattern: "tar *", reason: "Common project tar command after path protections pass." },
      { pattern: "unzip *", reason: "Common project unzip command after path protections pass." },
      { pattern: "zip *", reason: "Common project zip command after path protections pass." },
      { pattern: "gzip *", reason: "Common project gzip command after path protections pass." },
      { pattern: "gunzip *", reason: "Common project gunzip command after path protections pass." },
      { pattern: "gitleaks *", reason: "Common project gitleaks command." },
      { pattern: "trivy *", reason: "Common project trivy command." },
      { pattern: "grype *", reason: "Common project grype command." },
      { pattern: "snyk *", reason: "Common project snyk command." },
      { pattern: "ps *", reason: "Common project ps command." },
      { pattern: "cp *", reason: "Common project cp command." },
      { pattern: "mv *", reason: "Common project mv command." },
      { pattern: "test *", reason: "Common project test command." },
      { pattern: "[ *", reason: "Shell bracket test after path protections pass." },
      { pattern: "[[ *", reason: "Shell bracket test after path protections pass." },
      { pattern: "echo *", reason: "Common project echo command." },
      { pattern: "printf *", reason: "Common project printf command." },
      { pattern: "chmod *", reason: "Common project chmod command." },
      { pattern: "chown *", reason: "Common project chown command." },
      { pattern: "python *", reason: "Common project python command." },
      { pattern: "python3 *", reason: "Common project python3 command." },
      { pattern: "pip *", reason: "Common project pip command." },
      { pattern: "pip3 *", reason: "Common project pip3 command." },
      { pattern: "uv *", reason: "Common project uv command." },
      { pattern: "poetry *", reason: "Common project poetry command." },
      { pattern: "bash *.sh *", reason: "Common project bash command." },
      { pattern: "sh *.sh *", reason: "Common project sh command." },
      { pattern: "shellcheck --version", reason: "Check the installed ShellCheck version." },
      { pattern: "shellcheck *", reason: "Statically analyze shell scripts, with or without a .sh suffix." },
      { pattern: "bash -n *", reason: "Validate Bash syntax without execution." },
      { pattern: "sh -n *", reason: "Validate POSIX shell syntax without execution." },
      { pattern: "shfmt -d *", reason: "Check shell script formatting without modifying files." },
      { pattern: "shfmt -l *", reason: "List shell scripts requiring formatting." },
      { pattern: "checkbashisms *", reason: "Detect Bash-specific syntax." },
      { pattern: "bashate *", reason: "Lint shell scripts." },
      { pattern: "bats test/*.bats", reason: "Run trusted Bats shell tests." },
      { pattern: "make *", reason: "Common project make command." },
      { pattern: "just *", reason: "Common project just command." },
      { pattern: "task *", reason: "Common project task command." },
      { pattern: "pytest *", reason: "Common project pytest command." },
      { pattern: "ruff *", reason: "Common project ruff command." },
      { pattern: "cargo *", reason: "Common project cargo command." },
      { pattern: "go *", reason: "Common project go command." },
      { pattern: "docker *", reason: "Common project docker command." },
      { pattern: "set -*", reason: "Common project pipeline command." },
      { pattern: "date *", reason: "Common project date command." },
      { pattern: "sleep *", reason: "Common project sleep command." },
      { pattern: "uname *", reason: "Common project uname command." },
      { pattern: "whoami", reason: "Common project whoami command." },
      { pattern: "timeout *", reason: "Wrapped commands are still checked segment by segment." },
      { pattern: "time *", reason: "Wrapped commands are still checked segment by segment." },
      { pattern: "gh *", reason: "Common project github cli command." },
      { pattern: "which *", reason: "Common project which command." },
      { pattern: "pi *", reason: "Common project pi command." },
      { pattern: "tmux *", reason: "Common project tmux command." },
      { pattern: "agent-browser *", reason: "Common project agent-browser command." },
      { pattern: "lsof *", reason: "Port and open-file checks while running local servers." },
      { pattern: "kill *", reason: "Stopping processes the agent started, such as a local dev server." },
      { pattern: "rm *", reason: "Deleting concrete paths inside the project once path protections pass; the project root, globs, variables and outside paths still need approval." },
      { pattern: "rmdir *", reason: "Removing directories inside the project once path protections pass." },
      { pattern: "cd *", reason: "Directory change; the operand goes through path checks, so leaving the project still needs an allow rule." },
      { pattern: "export *", reason: "Shell variable export; PATH and loader variables are denied separately." },
      { pattern: "unset *", reason: "Shell variable unset." },
      { pattern: "exit *", reason: "Shell exit." },
      { pattern: "return *", reason: "Shell function return." },
      { pattern: "wait *", reason: "Wait for background jobs such as a dev server." },
      { pattern: "jobs *", reason: "List background jobs." },
      { pattern: "disown *", reason: "Detach a background job." },
      { pattern: "type *", reason: "Show how a command name resolves." },
      { pattern: "false", reason: "Shell no-op failure in compound commands." },
      { pattern: ":", reason: "Shell no-op." },
      { pattern: "read *", reason: "Read a line into a shell variable." },
      { pattern: "shift *", reason: "Shift positional parameters." },
      { pattern: "local *", reason: "Shell function local variable." },
      { pattern: "umask *", reason: "Show or set the file creation mask." },
      { pattern: "hash *", reason: "Command hash table." },
      { pattern: "mktemp *", reason: "Create temp files and directories." },
      { pattern: "ln *", reason: "Create links after path protections pass." },
      { pattern: "pkill *", reason: "Stopping processes the agent started by name, such as a local dev server." },
      { pattern: "wget *", reason: "Ordinary downloads after path protections pass; network policy is external." },
      { pattern: "sha1sum *", reason: "Checksum reads after path protections pass." },
      { pattern: "sha256sum *", reason: "Checksum reads after path protections pass." },
      { pattern: "sha512sum *", reason: "Checksum reads after path protections pass." },
      { pattern: "md5 *", reason: "Checksum reads after path protections pass." },
      { pattern: "md5sum *", reason: "Checksum reads after path protections pass." },
      { pattern: "base64 *", reason: "Encoding after path protections pass." },
      { pattern: "column *", reason: "Text formatting." },
      { pattern: "paste *", reason: "Text joining." },
      { pattern: "seq *", reason: "Number sequences." },
      { pattern: "expr *", reason: "Arithmetic." },
      { pattern: "bc *", reason: "Arithmetic." },
      { pattern: "cmp *", reason: "File comparison after path protections pass." },
      { pattern: "od *", reason: "Byte dumps after path protections pass." },
      { pattern: "xxd *", reason: "Byte dumps after path protections pass." },
      { pattern: "hexdump *", reason: "Byte dumps after path protections pass." },
      { pattern: "strings *", reason: "Printable strings after path protections pass." },
      { pattern: "tac *", reason: "Reverse file reads after path protections pass." },
      { pattern: "rev *", reason: "Reverse lines." },
      { pattern: "comm *", reason: "Sorted file comparison after path protections pass." },
      { pattern: "envsubst *", reason: "Template substitution after path protections pass." },
      { pattern: "netstat *", reason: "Port and socket inspection while running local servers." },
      { pattern: "ss *", reason: "Port and socket inspection while running local servers." },
      { pattern: "sqlite3 *", reason: "Local SQLite database files after path protections pass." },
      { pattern: "java *", reason: "Common project java command." },
      { pattern: "javac *", reason: "Common project javac command." },
      { pattern: "mvn *", reason: "Common project mvn command." },
      { pattern: "mvnw *", reason: "Common project mvnw command." },
      { pattern: "gradle *", reason: "Common project gradle command." },
      { pattern: "gradlew *", reason: "Common project gradlew command." },
      { pattern: "dotnet *", reason: "Common project dotnet command." },
      { pattern: "php *", reason: "Common project php command." },
      { pattern: "composer *", reason: "Common project composer command." },
      { pattern: "ruby *", reason: "Common project ruby command." },
      { pattern: "bundle *", reason: "Common project bundle command." },
      { pattern: "rake *", reason: "Common project rake command." },
      { pattern: "rustc *", reason: "Common project rustc command." },
      { pattern: "mypy *", reason: "Common project mypy command." },
      { pattern: "black *", reason: "Common project black command." },
      { pattern: "flake8 *", reason: "Common project flake8 command." },
      { pattern: "pylint *", reason: "Common project pylint command." },
      { pattern: "isort *", reason: "Common project isort command." },
      { pattern: "golangci-lint *", reason: "Common project golangci-lint command." },
      { pattern: "staticcheck *", reason: "Common project staticcheck command." },
      { pattern: "biome *", reason: "Common project biome command." },
      { pattern: "oxlint *", reason: "Common project oxlint command." },
      { pattern: "mocha *", reason: "Common project mocha command." },
      { pattern: "ava *", reason: "Common project ava command." },
      { pattern: "vite *", reason: "Common project vite command; also the segment npx runs when it launches vite." },
      { pattern: "serve *", reason: "Common project serve command; also the segment npx runs when it launches serve." },
      { pattern: "http-server *", reason: "Common project http-server command; also the segment npx runs when it launches http-server." },
      { pattern: "next *", reason: "Common project next command; also the segment npx runs when it launches next." },
      { pattern: "nuxt *", reason: "Common project nuxt command; also the segment npx runs when it launches nuxt." },
      { pattern: "astro *", reason: "Common project astro command; also the segment npx runs when it launches astro." },
      { pattern: "remix *", reason: "Common project remix command; also the segment npx runs when it launches remix." },
      { pattern: "ng *", reason: "Common project ng command; also the segment npx runs when it launches ng." },
      { pattern: "react-scripts *", reason: "Common project react-scripts command; also the segment npx runs when it launches react-scripts." },
      { pattern: "vue-cli-service *", reason: "Common project vue-cli-service command; also the segment npx runs when it launches vue-cli-service." },
      { pattern: "webpack *", reason: "Common project webpack command; also the segment npx runs when it launches webpack." },
      { pattern: "rollup *", reason: "Common project rollup command; also the segment npx runs when it launches rollup." },
      { pattern: "esbuild *", reason: "Common project esbuild command; also the segment npx runs when it launches esbuild." },
      { pattern: "parcel *", reason: "Common project parcel command; also the segment npx runs when it launches parcel." },
      { pattern: "turbo *", reason: "Common project turbo command; also the segment npx runs when it launches turbo." },
      { pattern: "nx *", reason: "Common project nx command; also the segment npx runs when it launches nx." },
      { pattern: "playwright *", reason: "Common project playwright command; also the segment npx runs when it launches playwright." },
      { pattern: "storybook *", reason: "Common project storybook command; also the segment npx runs when it launches storybook." },
      { pattern: "tailwindcss *", reason: "Common project tailwindcss command; also the segment npx runs when it launches tailwindcss." },
      { pattern: "postcss *", reason: "Common project postcss command; also the segment npx runs when it launches postcss." },
      { pattern: "tsup *", reason: "Common project tsup command; also the segment npx runs when it launches tsup." },
      { pattern: "wait-on *", reason: "Common project wait-on command; also the segment npx runs when it launches wait-on." },
      { pattern: "nodemon *", reason: "Common project nodemon command; also the segment npx runs when it launches nodemon." },
      { pattern: "terraform *", reason: "Infrastructure as Code checks: fmt, validate, init, plan, show, output. Apply, destroy, import, taint and state mutations are dangerous." },
      { pattern: "tofu *", reason: "OpenTofu checks: fmt, validate, init, plan, show, output. Apply, destroy, import, taint and state mutations are dangerous." },
      { pattern: "terragrunt *", reason: "Terragrunt wrapper for the same checks. Apply and destroy, including run-all, are dangerous." },
      { pattern: "tflint *", reason: "Terraform linting." },
      { pattern: "tfsec *", reason: "Terraform security scanning." },
      { pattern: "checkov *", reason: "Infrastructure as Code policy scanning." },
      { pattern: "packer fmt *", reason: "Packer template formatting check." },
      { pattern: "packer validate *", reason: "Packer template validation." },
      { pattern: "pulumi preview *", reason: "Pulumi change preview without deploying." },
      { pattern: "pulumi version", reason: "Check the installed Pulumi version." },
      { pattern: "helm *", reason: "Helm chart lint, template, dependency and repo commands. Install, upgrade, uninstall, rollback and delete are dangerous." },
      { pattern: "kubectl get *", reason: "Read-only cluster inspection." },
      { pattern: "kubectl describe *", reason: "Read-only cluster inspection." },
      { pattern: "kubectl explain *", reason: "Read-only API schema lookup." },
      { pattern: "kubectl api-resources*", reason: "Read-only API discovery." },
      { pattern: "kubectl version*", reason: "Check client and server versions." },
      { pattern: "kubectl config current-context", reason: "Show the active kubeconfig context." },
      { pattern: "kubectl config get-contexts*", reason: "List kubeconfig contexts." },
      { pattern: "kubectl kustomize *", reason: "Render kustomize overlays without applying." },
      { pattern: "kubectl diff *", reason: "Read-only diff of manifests against the cluster." },
      { pattern: "kubectl auth can-i *", reason: "Read-only permission check." },
      { pattern: "kustomize build *", reason: "Render kustomize overlays without applying." },
      { pattern: "kubeconform *", reason: "Kubernetes manifest schema validation." },
      { pattern: "kube-linter *", reason: "Kubernetes manifest linting." },
      { pattern: "hadolint *", reason: "Dockerfile linting." },
      { pattern: "actionlint *", reason: "GitHub Actions workflow linting." },
      { pattern: "yamllint *", reason: "YAML linting." },
      { pattern: "ansible-lint *", reason: "Ansible playbook linting." },
      { pattern: "ansible-playbook *--syntax-check*", reason: "Ansible syntax check without touching hosts." },
      { pattern: "ansible-playbook *--check*", reason: "Ansible dry run without changing hosts." },
    ],
    denyPaths: [
      {
        pattern: "**/.env",
        actions: ALL_PATH_ACTIONS,
        reason: "Environment files may contain credentials.",
      },
      {
        pattern: "**/.env.*",
        actions: ["delete", "move", "rename"],
        reason:
          "Env file variants must not be deleted, moved, or renamed. Non-template variants such as .env.local are also read/write protected by the built-in credential classifier.",
      },
      {
        pattern: "**/.npmrc",
        actions: ALL_PATH_ACTIONS,
        reason: "npm config may contain registry tokens.",
      },
      {
        pattern: "**/.pypirc",
        actions: ALL_PATH_ACTIONS,
        reason: "Python package config may contain publish tokens.",
      },
      {
        pattern: "**/.netrc",
        actions: ALL_PATH_ACTIONS,
        reason: "netrc files may contain machine credentials.",
      },
    ],
    zeroAccessPaths: [
      {
        pattern: "~/.ssh/**",
        actions: ALL_PATH_ACTIONS,
        reason: "SSH keys and config are never available to LLM tool calls.",
      },
      {
        pattern: "~/.pi/agent/auth.json",
        actions: ALL_PATH_ACTIONS,
        reason: "Pi credentials are never available to LLM tool calls.",
      },
      {
        pattern: "~/.gnupg/**",
        actions: ALL_PATH_ACTIONS,
        reason: "GPG keys and trust material are never available to LLM tool calls.",
      },
      {
        pattern: "~/.1password/**",
        actions: ALL_PATH_ACTIONS,
        reason: "Password-manager local data is never available to LLM tool calls.",
      },
    ],
    readOnlyPaths: [
      {
        pattern: "**/.pi/**",
        actions: ["read", "list"],
        reason: "Project GuardMe policy should be changed through /guardme or explicit user edits.",
      },
      {
        pattern: ".pi/agent/guardme.yaml",
        actions: ["read", "list"],
        reason: "Project GuardMe policy should be changed through /guardme or explicit user edits.",
      },
      {
        pattern: "~/.pi/agent/guardme.yaml",
        actions: ["read", "list"],
        reason: "Global GuardMe policy should be changed through /guardme or explicit user edits.",
      },
      {
        pattern: ".pi/agent/guardme-settings.json",
        actions: ["read", "list"],
        reason: "Project GuardMe runtime settings should be changed through /guardme.",
      },
      {
        pattern: ".git/**",
        actions: ["read", "list"],
        reason: "Repository metadata is read-only for direct writes; change it through git commands.",
      },
      {
        pattern: "**/.git/**",
        actions: ["read", "list"],
        reason: "Repository metadata is read-only for direct writes; change it through git commands.",
      },
    ],
    noDeletePaths: [
      {
        pattern: ".git",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: ".git/**",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: "**/.git",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: "**/.git/**",
        actions: ["delete", "move", "rename"],
        reason: "Repository metadata must not be deleted, moved, or renamed.",
      },
      {
        pattern: "package-lock.json",
        actions: ["delete", "move", "rename"],
        reason: "Package lockfiles should not be removed without explicit user intent.",
      },
      {
        pattern: "pnpm-lock.yaml",
        actions: ["delete", "move", "rename"],
        reason: "Package lockfiles should not be removed without explicit user intent.",
      },
      {
        pattern: "yarn.lock",
        actions: ["delete", "move", "rename"],
        reason: "Package lockfiles should not be removed without explicit user intent.",
      },
    ],
    denyCommands: [
      { pattern: "aws", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "aws *", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "az", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "az *", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "gcloud", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "gcloud *", reason: "Cloud CLIs are always denied by GuardMe." },
      { pattern: "sudo *", reason: "Privilege escalation is blocked by default." },
      { pattern: "sudoedit *", reason: "Privilege escalation is blocked by default." },
      { pattern: "doas *", reason: "Privilege escalation is blocked by default." },
      { pattern: "chmod 777 *", reason: "World-writable permissions are unsafe by default." },
      { pattern: "env", reason: "Bare 'env' prints all environment variables, which may contain secrets." },
      { pattern: "printenv", reason: "'printenv' prints environment variables, which may contain secrets." },
      { pattern: "printenv *", reason: "'printenv' prints environment variables, which may contain secrets." },
      { pattern: "gh auth token*", reason: "'gh auth token' prints the GitHub OAuth token." },
      { pattern: "git credential*", reason: "git credential helpers print stored credentials." },
      { pattern: "npm config get *_authToken*", reason: "npm config can print registry auth tokens." },
      { pattern: "export PATH=*", reason: "Exporting PATH can redirect which programs later segments run." },
      { pattern: "export \"PATH=*", reason: "Exporting PATH can redirect which programs later segments run." },
      { pattern: "export LD_PRELOAD=*", reason: "Exporting LD_PRELOAD can redirect which programs later segments run." },
      { pattern: "export \"LD_PRELOAD=*", reason: "Exporting LD_PRELOAD can redirect which programs later segments run." },
      { pattern: "export LD_LIBRARY_PATH=*", reason: "Exporting LD_LIBRARY_PATH can redirect which programs later segments run." },
      { pattern: "export \"LD_LIBRARY_PATH=*", reason: "Exporting LD_LIBRARY_PATH can redirect which programs later segments run." },
      { pattern: "export DYLD_INSERT_LIBRARIES=*", reason: "Exporting DYLD_INSERT_LIBRARIES can redirect which programs later segments run." },
      { pattern: "export \"DYLD_INSERT_LIBRARIES=*", reason: "Exporting DYLD_INSERT_LIBRARIES can redirect which programs later segments run." },
      { pattern: "export DYLD_LIBRARY_PATH=*", reason: "Exporting DYLD_LIBRARY_PATH can redirect which programs later segments run." },
      { pattern: "export \"DYLD_LIBRARY_PATH=*", reason: "Exporting DYLD_LIBRARY_PATH can redirect which programs later segments run." },
      { pattern: "export NODE_OPTIONS=*", reason: "Exporting NODE_OPTIONS can redirect which programs later segments run." },
      { pattern: "export \"NODE_OPTIONS=*", reason: "Exporting NODE_OPTIONS can redirect which programs later segments run." },
      { pattern: "export BASH_ENV=*", reason: "Exporting BASH_ENV can redirect which programs later segments run." },
      { pattern: "export \"BASH_ENV=*", reason: "Exporting BASH_ENV can redirect which programs later segments run." },
    ],
    dangerousCommands: [
      { pattern: "git clean -f*", reason: "Forced git clean can remove untracked work." },
      { pattern: "find * -delete", reason: "find -delete can remove many files." },
      { pattern: "rsync * --delete*", reason: "rsync --delete can remove destination files." },
      { pattern: "git apply*", reason: "git apply writes files without content scanning or path protections." },
      { pattern: "git * core.hooksPath*", reason: "Custom git hook paths can run arbitrary code on later git commands." },
      { pattern: "npm pkg set*", reason: "npm pkg set edits package.json scripts without content scanning." },
      { pattern: "npm set-script*", reason: "npm set-script edits package.json scripts without content scanning." },
      { pattern: "terraform apply*", reason: "Applies infrastructure changes to a live environment." },
      { pattern: "terraform destroy*", reason: "Destroys live infrastructure." },
      { pattern: "terraform import*", reason: "Mutates Terraform state." },
      { pattern: "terraform taint*", reason: "Mutates Terraform state." },
      { pattern: "terraform untaint*", reason: "Mutates Terraform state." },
      { pattern: "terraform state mv*", reason: "Mutates Terraform state." },
      { pattern: "terraform state rm*", reason: "Mutates Terraform state." },
      { pattern: "terraform state push*", reason: "Overwrites remote Terraform state." },
      { pattern: "terraform force-unlock*", reason: "Breaks a state lock another run may hold." },
      { pattern: "terraform workspace delete*", reason: "Deletes a Terraform workspace." },
      { pattern: "tofu apply*", reason: "Applies infrastructure changes to a live environment." },
      { pattern: "tofu destroy*", reason: "Destroys live infrastructure." },
      { pattern: "tofu import*", reason: "Mutates OpenTofu state." },
      { pattern: "tofu taint*", reason: "Mutates OpenTofu state." },
      { pattern: "tofu untaint*", reason: "Mutates OpenTofu state." },
      { pattern: "tofu state mv*", reason: "Mutates OpenTofu state." },
      { pattern: "tofu state rm*", reason: "Mutates OpenTofu state." },
      { pattern: "tofu state push*", reason: "Overwrites remote OpenTofu state." },
      { pattern: "tofu force-unlock*", reason: "Breaks a state lock another run may hold." },
      { pattern: "tofu workspace delete*", reason: "Deletes an OpenTofu workspace." },
      { pattern: "terragrunt apply*", reason: "Applies infrastructure changes to a live environment." },
      { pattern: "terragrunt destroy*", reason: "Destroys live infrastructure." },
      { pattern: "terragrunt run-all apply*", reason: "Applies infrastructure changes across modules." },
      { pattern: "terragrunt run-all destroy*", reason: "Destroys infrastructure across modules." },
      { pattern: "helm install*", reason: "Deploys a release to a cluster." },
      { pattern: "helm upgrade*", reason: "Changes a release on a cluster." },
      { pattern: "helm uninstall*", reason: "Removes a release from a cluster." },
      { pattern: "helm delete*", reason: "Removes a release from a cluster." },
      { pattern: "helm rollback*", reason: "Changes a release on a cluster." },
      { pattern: "docker push*", reason: "Publishes an image to a registry." },
      { pattern: "docker compose push*", reason: "Publishes images to a registry." },
      { pattern: "docker buildx * --push*", reason: "Publishes an image to a registry." },
      { pattern: "docker login*", reason: "Registry authentication handles credentials." },
      { pattern: "docker system prune*", reason: "Removes local images, containers, networks and build cache." },
      { pattern: "docker volume prune*", reason: "Removes local volumes and their data." },
      { pattern: "docker volume rm*", reason: "Removes local volumes and their data." },
    ],
    protectedCredentialPaths: [
      { pattern: "~/.aws/**", actions: ALL_PATH_ACTIONS, reason: "AWS credentials are protected." },
      { pattern: "~/.azure/**", actions: ALL_PATH_ACTIONS, reason: "Azure credentials are protected." },
      { pattern: "~/.config/gcloud/**", actions: ALL_PATH_ACTIONS, reason: "Google Cloud credentials are protected." },
      { pattern: "~/.docker/config.json", actions: ALL_PATH_ACTIONS, reason: "Docker registry credentials are protected." },
      { pattern: "~/.kube/**", actions: ALL_PATH_ACTIONS, reason: "Kubernetes cluster credentials are protected." },
      { pattern: "~/.terraform.d/**", actions: ALL_PATH_ACTIONS, reason: "Terraform Cloud credentials are protected." },
      { pattern: "~/.terraformrc", actions: ALL_PATH_ACTIONS, reason: "Terraform CLI config may hold credentials." },
      { pattern: "~/.pulumi/credentials.json", actions: ALL_PATH_ACTIONS, reason: "Pulumi credentials are protected." },
      { pattern: "~/.config/helm/**", actions: ALL_PATH_ACTIONS, reason: "Helm registry credentials are protected." },
      { pattern: "~/.npmrc", actions: ALL_PATH_ACTIONS, reason: "npm tokens are protected." },
      { pattern: "~/.netrc", actions: ALL_PATH_ACTIONS, reason: "Machine credentials are protected." },
      // Keyword-named files (secrets.yaml, my-token.txt, credentials.json) are
      // hard-denied by the built-in credential path classifier, which matches
      // on word boundaries. Substring globs such as **/*token* are deliberately
      // absent because they also blocked code files like tokenizer.ts.
    ],
  };
}

export function validateGuardMeConfig(input: unknown, source: RuleSource): ConfigValidationResult {
  const diagnostics: PolicyDiagnostic[] = [];
  const config = createEmptyPolicyConfig(POLICY_VERSION);

  if (!isRecord(input)) {
    diagnostics.push(configDiagnostic("error", "config.invalidRoot", "GuardMe policy must be a YAML object.", source));
    return { config, diagnostics };
  }

  let versionSupported = true;
  const version = input.version;
  if (version !== undefined) {
    if (typeof version !== "number" || !Number.isInteger(version)) {
      versionSupported = false;
      diagnostics.push(configDiagnostic("error", "config.invalidVersion", "Policy version must be an integer.", source));
    } else if (version !== POLICY_VERSION) {
      versionSupported = false;
      diagnostics.push(
        configDiagnostic("error", "config.unsupportedVersion", `Unsupported GuardMe policy version ${version}.`, source),
      );
    }
  }

  const approvalMode = validateApprovalMode(input.approvalMode, source, diagnostics);
  const guardedTools = validateGuardedTools(input.guardedTools, source, diagnostics);
  const normalized: Record<PolicyConfigSection, readonly GuardMeRule[]> = Object.fromEntries(
    POLICY_CONFIG_SECTIONS.map((section) => [section, validateRuleSection(section, input[section], source, diagnostics)]),
  ) as Record<PolicyConfigSection, readonly GuardMeRule[]>;

  for (const key of Object.keys(input)) {
    if (key !== "version" && key !== "approvalMode" && key !== "guardedTools" && !POLICY_CONFIG_SECTION_SET.has(key)) {
      diagnostics.push(configDiagnostic("warning", "config.unknownKey", `Unknown GuardMe policy key '${key}' ignored.`, source));
    }
  }

  if (!versionSupported) {
    return { config, diagnostics };
  }

  return {
    config: {
      ...config,
      ...(approvalMode ? { approvalMode } : {}),
      guardedTools,
      allowPaths: normalized.allowPaths as readonly GuardMePathRule[],
      denyPaths: normalized.denyPaths as readonly GuardMePathRule[],
      zeroAccessPaths: normalized.zeroAccessPaths as readonly GuardMePathRule[],
      readOnlyPaths: normalized.readOnlyPaths as readonly GuardMePathRule[],
      noDeletePaths: normalized.noDeletePaths as readonly GuardMePathRule[],
      allowCommands: normalized.allowCommands,
      denyCommands: normalized.denyCommands,
      dangerousCommands: normalized.dangerousCommands,
      protectedCredentialPaths: normalized.protectedCredentialPaths as readonly GuardMePathRule[],
    },
    diagnostics,
  };
}

export function parsePolicyYaml(text: string, source: RuleSource): ParsePolicyYamlResult {
  const state: PolicyYamlParseState = {
    data: {},
    diagnostics: [],
    source,
  };

  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = parseYamlLine(rawLine, index);
    if (!line) {
      continue;
    }
    parsePolicyYamlLine(line, state);
  }

  return { data: state.data, diagnostics: state.diagnostics };
}

interface ParsedYamlLine {
  readonly lineNumber: number;
  readonly withoutComment: string;
  readonly indent: number;
  readonly trimmed: string;
}

interface PolicyYamlParseState {
  readonly data: Record<string, unknown>;
  readonly diagnostics: PolicyDiagnostic[];
  readonly source: RuleSource;
  currentSection?: PolicyConfigSection | "guardedTools";
  currentItem?: Record<string, unknown>;
}

function parseYamlLine(rawLine: string, index: number): ParsedYamlLine | undefined {
  const withoutComment = stripYamlComment(rawLine);
  const trimmed = withoutComment.trim();
  if (trimmed === "") {
    return undefined;
  }
  return {
    lineNumber: index + 1,
    withoutComment,
    indent: countLeadingSpaces(withoutComment),
    trimmed,
  };
}

function parsePolicyYamlLine(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  if (line.indent === 0) {
    parsePolicyYamlTopLevelLine(line, state);
    return;
  }
  parsePolicyYamlNestedLine(line, state);
}

function parsePolicyYamlTopLevelLine(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  state.currentSection = undefined;
  state.currentItem = undefined;
  const parsed = parseKeyValue(line.trimmed);
  if (!parsed) {
    state.diagnostics.push(lineDiagnostic("error", "yaml.expectedKeyValue", "Expected a top-level key/value pair.", state.source, line.lineNumber));
    return;
  }

  const [key, valueText] = parsed;
  if (key === "version") {
    state.data.version = parseScalar(valueText);
    return;
  }
  if (key === "approvalMode") {
    state.data.approvalMode = parseScalar(valueText);
    return;
  }
  if (key === "guardedTools") {
    if (valueText.trim() !== "") {
      state.diagnostics.push(lineDiagnostic("error", "yaml.guardedToolsMustBeMap", "Section 'guardedTools' must be written as a YAML mapping.", state.source, line.lineNumber));
      state.data.guardedTools = parseScalar(valueText);
      return;
    }
    state.currentSection = "guardedTools";
    if (isRecord(state.data.guardedTools)) {
      state.diagnostics.push(
        lineDiagnostic("warning", "yaml.duplicateSection", "Duplicate section 'guardedTools' merges with the earlier block.", state.source, line.lineNumber),
      );
      return;
    }
    state.data.guardedTools = {};
    return;
  }
  if (!isPolicyConfigSection(key)) {
    state.data[key] = parseScalar(valueText);
    return;
  }
  if (valueText.trim() !== "") {
    state.diagnostics.push(
      lineDiagnostic("error", "yaml.sectionMustBeList", `Section '${key}' must be written as a YAML list.`, state.source, line.lineNumber),
    );
    state.data[key] = parseScalar(valueText);
    return;
  }
  state.currentSection = key;
  if (Array.isArray(state.data[key])) {
    state.diagnostics.push(
      lineDiagnostic("warning", "yaml.duplicateSection", `Duplicate section '${key}' merges with the earlier '${key}' block.`, state.source, line.lineNumber),
    );
    return;
  }
  state.data[key] = [];
}

function parsePolicyYamlNestedLine(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  if (!state.currentSection) {
    state.diagnostics.push(lineDiagnostic("error", "yaml.unexpectedIndent", "Unexpected indented line outside a section.", state.source, line.lineNumber));
    return;
  }
  if (state.currentSection === "guardedTools") {
    parseGuardedToolMappingLine(line, state);
    return;
  }
  if (line.indent === 2 && line.trimmed.startsWith("-")) {
    parsePolicyYamlListItem(line, state, state.currentSection);
    return;
  }
  if (line.indent >= 4 && state.currentItem) {
    parsePolicyYamlRuleProperty(line, state);
    return;
  }
  state.diagnostics.push(lineDiagnostic("error", "yaml.invalidIndent", "Invalid indentation for GuardMe policy YAML.", state.source, line.lineNumber));
}

function parseGuardedToolMappingLine(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  const parsed = line.indent === 2 ? parseKeyValue(line.trimmed) : undefined;
  const parsedName = parsed ? parseScalar(parsed[0]) : undefined;
  if (!parsed || typeof parsedName !== "string" || parsedName === "") {
    state.diagnostics.push(lineDiagnostic("error", "yaml.invalidGuardedToolMapping", "Guarded tool mappings must use 'toolName: builtInContract' entries.", state.source, line.lineNumber));
    return;
  }
  const mappings = state.data.guardedTools as Record<string, unknown>;
  if (Object.hasOwn(mappings, parsedName)) {
    state.diagnostics.push(lineDiagnostic("error", "yaml.duplicateGuardedTool", `Duplicate guarded tool mapping '${parsedName}'.`, state.source, line.lineNumber));
    return;
  }
  mappings[parsedName] = parseScalar(parsed[1]);
}

function parsePolicyYamlListItem(line: ParsedYamlLine, state: PolicyYamlParseState, section: PolicyConfigSection): void {
  const currentItem: Record<string, unknown> = {};
  state.currentItem = currentItem;
  (state.data[section] as Record<string, unknown>[]).push(currentItem);
  const itemText = line.trimmed.slice(1).trim();
  if (itemText === "") {
    return;
  }
  const parsedItem = parseKeyValue(itemText);
  if (parsedItem) {
    currentItem[parsedItem[0]] = parseScalar(parsedItem[1]);
    return;
  }
  currentItem.pattern = parseScalar(itemText);
}

function parsePolicyYamlRuleProperty(line: ParsedYamlLine, state: PolicyYamlParseState): void {
  const parsed = parseKeyValue(line.trimmed);
  if (!parsed) {
    state.diagnostics.push(lineDiagnostic("error", "yaml.expectedRuleProperty", "Expected a rule property key/value pair.", state.source, line.lineNumber));
    return;
  }
  state.currentItem![parsed[0]] = parseScalar(parsed[1]);
}

function isPolicyConfigSection(value: string): value is PolicyConfigSection {
  return POLICY_CONFIG_SECTION_SET.has(value);
}

function validateApprovalMode(
  value: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): ApprovalMode | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (isApprovalMode(value)) {
    return value;
  }
  diagnostics.push(
    configDiagnostic(
      "error",
      "config.invalidApprovalMode",
      "GuardMe approvalMode must be one of: auto, interactive, agent, block. GuardMe is using block mode for this policy source.",
      source,
    ),
  );
  return "block";
}

function validateGuardedTools(
  value: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): Readonly<Record<string, GuardedToolContract>> {
  if (value === undefined) {
    return {};
  }
  if (!isRecord(value)) {
    diagnostics.push(configDiagnostic("error", "config.guardedToolsNotMap", "GuardMe guardedTools must be a mapping of custom tool names to built-in contracts.", source));
    return {};
  }
  const mappings: Record<string, GuardedToolContract> = {};
  for (const [rawName, rawContract] of Object.entries(value)) {
    const name = rawName.trim();
    if (name === "") {
      diagnostics.push(configDiagnostic("error", "config.emptyGuardedToolName", "Guarded tool names must not be empty.", source));
      continue;
    }
    if (Object.hasOwn(BUILT_IN_GUARDED_TOOLS, name)) {
      diagnostics.push(configDiagnostic("error", "config.reservedGuardedTool", `Built-in guarded tool '${name}' cannot be remapped.`, source));
      continue;
    }
    if (typeof rawContract !== "string" || !(GUARDED_TOOL_NAMES as readonly string[]).includes(rawContract)) {
      diagnostics.push(configDiagnostic("error", "config.invalidGuardedToolContract", `Guarded tool '${name}' must map to one of: ${GUARDED_TOOL_NAMES.join(", ")}.`, source));
      continue;
    }
    mappings[name] = rawContract as GuardedToolContract;
  }
  return mappings;
}

function validateRuleSection(
  section: PolicyConfigSection,
  value: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): readonly GuardMeRule[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    diagnostics.push(configDiagnostic("error", "config.sectionNotArray", `Section '${section}' must be a list.`, source));
    return [];
  }

  const rules: GuardMeRule[] = [];
  for (const [index, rawRule] of value.entries()) {
    const ruleSource = { ...source, index };
    const rule = validateRule(section, rawRule, ruleSource, diagnostics);
    if (rule) {
      rules.push(rule);
    }
  }
  return rules;
}

const KNOWN_RULE_KEYS: ReadonlySet<string> = new Set(["pattern", "actions", "reason"]);

function reportUnknownRuleKeys(
  section: PolicyConfigSection,
  rawRule: Record<string, unknown>,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): void {
  for (const key of Object.keys(rawRule)) {
    if (!KNOWN_RULE_KEYS.has(key)) {
      const hint = key === "action" ? " Did you mean 'actions'? Without 'actions', the rule applies to every action." : "";
      diagnostics.push(configDiagnostic("warning", "config.unknownRuleKey", `Unknown rule key '${key}' in '${section}' ignored.${hint}`, source));
    }
  }
}

function createValidatedRule(pattern: string, actions: readonly PolicyAction[], reason: unknown): GuardMeRule {
  return {
    pattern: pattern.trim(),
    ...(actions.length > 0 ? { actions } : {}),
    ...(typeof reason === "string" ? { reason } : {}),
  };
}

function validateRule(
  section: PolicyConfigSection,
  rawRule: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): GuardMeRule | undefined {
  if (typeof rawRule === "string") {
    return { pattern: rawRule };
  }

  if (!isRecord(rawRule)) {
    diagnostics.push(configDiagnostic("error", "config.ruleNotObject", `Rule in '${section}' must be an object or string pattern.`, source));
    return undefined;
  }

  reportUnknownRuleKeys(section, rawRule, source, diagnostics);

  if (typeof rawRule.pattern !== "string" || rawRule.pattern.trim() === "") {
    diagnostics.push(configDiagnostic("error", "config.missingPattern", `Rule in '${section}' must include a non-empty pattern.`, source));
    return undefined;
  }

  const validatedActions = validateActions(section, rawRule.actions, source, diagnostics);
  if (!validatedActions.usable) {
    if (!DENY_DIRECTION_SECTION_SET.has(section)) {
      return undefined;
    }
    diagnostics.push(
      configDiagnostic(
        "error",
        "config.denyRuleActionsFallback",
        `Rule in '${section}' has invalid actions; GuardMe applies it to all actions as a fail-safe.`,
        source,
      ),
    );
  }
  const actions = validatedActions.usable ? validatedActions.actions : [];
  const reason = rawRule.reason;
  if (reason !== undefined && typeof reason !== "string") {
    diagnostics.push(configDiagnostic("error", "config.invalidReason", `Rule reason in '${section}' must be a string.`, source));
  }

  return createValidatedRule(rawRule.pattern, actions, reason);
}

const DENY_DIRECTION_SECTION_SET: ReadonlySet<PolicyConfigSection> = new Set([
  "denyPaths",
  "zeroAccessPaths",
  "readOnlyPaths",
  "noDeletePaths",
  "protectedCredentialPaths",
  "denyCommands",
  "dangerousCommands",
]);

interface ActionValidationResult {
  readonly actions: readonly PolicyAction[];
  readonly usable: boolean;
}

function validateActions(
  section: PolicyConfigSection,
  value: unknown,
  source: RuleSource,
  diagnostics: PolicyDiagnostic[],
): ActionValidationResult {
  if (value === undefined) {
    return { actions: [], usable: true };
  }

  if (COMMAND_RULE_SECTION_SET.has(section)) {
    diagnostics.push(
      configDiagnostic(
        "error",
        "config.commandActionsUnsupported",
        `Command rules in '${section}' do not support actions; split behavior by command pattern instead.`,
        source,
      ),
    );
    return { actions: [], usable: false };
  }

  if (!Array.isArray(value)) {
    diagnostics.push(configDiagnostic("error", "config.actionsNotArray", `Rule actions in '${section}' must be a list.`, source));
    return { actions: [], usable: false };
  }

  if (value.length === 0) {
    diagnostics.push(configDiagnostic("error", "config.actionsEmpty", `Rule actions in '${section}' must include at least one action or be omitted.`, source));
    return { actions: [], usable: false };
  }

  let invalidActionFound = false;
  const actions: PolicyAction[] = [];
  for (const rawAction of value) {
    if (typeof rawAction !== "string" || !isPolicyAction(rawAction)) {
      invalidActionFound = true;
      diagnostics.push(configDiagnostic("error", "config.invalidAction", `Invalid policy action '${String(rawAction)}'.`, source));
      continue;
    }
    if (PATH_RULE_SECTION_SET.has(section) && rawAction === "shell") {
      invalidActionFound = true;
      diagnostics.push(configDiagnostic("error", "config.invalidPathAction", "Path rules cannot use the shell action.", source));
      continue;
    }
    if (!actions.includes(rawAction)) {
      actions.push(rawAction);
    }
  }
  return { actions, usable: actions.length > 0 || !invalidActionFound };
}

function parseKeyValue(text: string): readonly [string, string] | undefined {
  const colonIndex = text.indexOf(":");
  if (colonIndex < 0) {
    return undefined;
  }
  return [text.slice(0, colonIndex).trim(), text.slice(colonIndex + 1).trim()];
}

function parseScalar(text: string): unknown {
  const trimmed = text.trim();
  if (trimmed === "") {
    return "";
  }
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const inner = trimmed.slice(1, -1).trim();
    return inner === "" ? [] : inner.split(",").map((part) => parseScalar(part));
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed) as unknown;
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replaceAll("''", "'");
  }
  if (/^-?\d+$/.test(trimmed)) {
    return Number.parseInt(trimmed, 10);
  }
  return trimmed;
}

function stripYamlComment(line: string): string {
  const commentIndex = findYamlCommentIndex(line);
  return commentIndex < 0 ? line : line.slice(0, commentIndex);
}

type YamlQuote = '"' | "'";

interface YamlQuoteScanResult {
  readonly quote: YamlQuote | undefined;
  readonly skipNext: boolean;
  readonly handled: boolean;
}

function findYamlCommentIndex(line: string): number {
  let quote: YamlQuote | undefined;
  for (let index = 0; index < line.length; index += 1) {
    const quoted = scanQuotedYamlCharacter(line, index, quote);
    if (quoted.handled) {
      quote = quoted.quote;
      if (quoted.skipNext) {
        index += 1;
      }
      continue;
    }

    const character = line[index];
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (isYamlCommentStart(line, index)) {
      return index;
    }
  }
  return -1;
}

function scanQuotedYamlCharacter(line: string, index: number, quote: YamlQuote | undefined): YamlQuoteScanResult {
  if (!quote) {
    return { quote, skipNext: false, handled: false };
  }
  const character = line[index];
  if (quote === "'" && character === "'" && line[index + 1] === "'") {
    return { quote, skipNext: true, handled: true };
  }
  if (character === quote && quote === "'") {
    return { quote: undefined, skipNext: false, handled: true };
  }
  if (character === '"' && quote === '"' && !isEscapedDoubleQuote(line, index)) {
    return { quote: undefined, skipNext: false, handled: true };
  }
  return { quote, skipNext: false, handled: true };
}

function isYamlCommentStart(line: string, index: number): boolean {
  return line[index] === "#" && (index === 0 || /\s/u.test(line[index - 1] ?? ""));
}

function isEscapedDoubleQuote(line: string, quoteIndex: number): boolean {
  let backslashCount = 0;
  for (let index = quoteIndex - 1; index >= 0 && line[index] === "\\"; index -= 1) {
    backslashCount += 1;
  }
  return backslashCount % 2 === 1;
}

function countLeadingSpaces(line: string): number {
  const match = /^ */u.exec(line);
  return match?.[0].length ?? 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function configDiagnostic(
  severity: PolicyDiagnostic["severity"],
  code: string,
  message: string,
  source: RuleSource,
): PolicyDiagnostic {
  return { severity, code, message, source };
}

function lineDiagnostic(
  severity: PolicyDiagnostic["severity"],
  code: string,
  message: string,
  source: RuleSource,
  line: number,
): PolicyDiagnostic {
  return { severity, code, message, source, ruleIndex: line };
}

export function createRuleSource(kind: RuleSourceKind, path?: string): RuleSource {
  return { kind, ...(path ? { path } : {}) };
}
