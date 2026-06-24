import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

export const FAKE_ENV_SECRET = "guardme-e2e-fake-token-do-not-leak";
export const OUTSIDE_READ_DIR = "/tmp/guardme-e2e-outside-read";
export const OUTSIDE_WRITE_DIR = "/tmp/guardme-e2e-outside-write";
export const OUTSIDE_DELETE_DIR = "/tmp/guardme-e2e-outside-delete";
export const OUTSIDE_READ_PATH = `${OUTSIDE_READ_DIR}/file.txt`;
export const OUTSIDE_WRITE_PATH = `${OUTSIDE_WRITE_DIR}/file.txt`;
export const OUTSIDE_DELETE_PATH = `${OUTSIDE_DELETE_DIR}/file.txt`;

export const SAFE_SCRIPT_CONTENT = "#!/bin/sh\necho safe\n";
export const SAFE_NOTE_CONTENT = "original safe note\n";
export const EDITED_SAFE_NOTE_CONTENT = "edited safe note\n";

const FIXTURE_PREFIX = "/tmp/guardme-e2e-";

export async function createProjectFixture(label = "rpc") {
  const rootDir = await mkdtemp(`${FIXTURE_PREFIX}${label}-`);
  const homeDir = join(rootDir, "home");
  const projectDir = join(rootDir, "project");
  const markerPath = join(projectDir, "tmp", "e2e-unsafe-marker.txt");
  const approvalTargetPath = join(projectDir, "approval-target", "file.txt");
  const denyTargetPath = join(projectDir, "deny-target", "file.txt");
  const safeNotePath = join(projectDir, "notes.txt");
  const safeWritePath = join(projectDir, "tmp", "safe-write.txt");
  const gitHeadPath = join(projectDir, ".git", "HEAD");
  const localPolicyPath = join(projectDir, ".pi", "agent", "guardme.yaml");
  const globalPolicyPath = join(homeDir, ".pi", "agent", "guardme.yaml");
  const localStatePath = join(projectDir, ".pi", "agent", "guardme-state.jsonl");
  const globalStatePath = join(homeDir, ".pi", "agent", "guardme-state.jsonl");

  await mkdir(homeDir, { recursive: true });
  await mkdir(projectDir, { recursive: true });
  await populateProject(projectDir);
  await recreateOutsideFiles();
  await recreateApprovalTarget(projectDir);

  return {
    rootDir,
    homeDir,
    projectDir,
    markerPath,
    approvalTargetPath,
    denyTargetPath,
    safeNotePath,
    safeWritePath,
    gitHeadPath,
    localPolicyPath,
    globalPolicyPath,
    localStatePath,
    globalStatePath,
    async recreateEnvTest() {
      await recreateEnvTest(projectDir);
    },
    async recreateBuild() {
      await recreateBuild(projectDir);
    },
    async recreateOutsideFiles() {
      await recreateOutsideFiles();
    },
    async recreateApprovalTarget() {
      await recreateApprovalTarget(projectDir);
    },
    async recreateDenyTarget() {
      await recreateDenyTarget(projectDir);
    },
    async recreateGitMetadata() {
      await recreateGitMetadata(projectDir);
    },
    async recreateSafeNote() {
      await writeFile(safeNotePath, SAFE_NOTE_CONTENT, "utf8");
    },
    async removeMarker() {
      await rm(markerPath, { force: true });
    },
    async readLocalPolicy() {
      return readIfExists(localPolicyPath);
    },
    async readLocalState() {
      return readIfExists(localStatePath);
    },
    async cleanup() {
      await safeRm(rootDir);
      await Promise.all([safeRm(OUTSIDE_READ_DIR), safeRm(OUTSIDE_WRITE_DIR), safeRm(OUTSIDE_DELETE_DIR)]);
    },
  };
}

export async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function readIfExists(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return "";
    }
    throw error;
  }
}

async function populateProject(projectDir) {
  await mkdir(join(projectDir, "scripts"), { recursive: true });
  await mkdir(join(projectDir, "tmp"), { recursive: true });
  await recreateBuild(projectDir);
  await recreateEnvTest(projectDir);

  await writeFile(join(projectDir, "README.md"), "# GuardMe e2e fixture\n\nThis file is safe to read in e2e tests.\n", "utf8");
  await writeFile(join(projectDir, "notes.txt"), SAFE_NOTE_CONTENT, "utf8");
  await writeFile(
    join(projectDir, "package.json"),
    `${JSON.stringify(
      {
        name: "guardme-e2e-fixture",
        version: "0.0.0",
        private: true,
        type: "module",
        scripts: {
          test: "node scripts/test-help.mjs",
        },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(join(projectDir, "scripts", "test-help.mjs"), "console.log('guardme e2e validation ok');\n", "utf8");
  await writeFile(join(projectDir, "scripts", "safe.sh"), SAFE_SCRIPT_CONTENT, "utf8");
  await writeFile(
    join(projectDir, "scripts", "unsafe.sh"),
    `#!/bin/sh\ncat .env\nmkdir -p tmp\necho unsafe-ran > tmp/e2e-unsafe-marker.txt\n`,
    "utf8",
  );
  await chmod(join(projectDir, "scripts", "safe.sh"), 0o755);
  await chmod(join(projectDir, "scripts", "unsafe.sh"), 0o755);
}

async function recreateEnvTest(projectDir) {
  await writeFile(
    join(projectDir, ".env"),
    `GUARDME_E2E_FAKE_TOKEN=${FAKE_ENV_SECRET}\nGUARDME_E2E_FAKE_SECRET=not-real\n`,
    "utf8",
  );
}

async function recreateBuild(projectDir) {
  await mkdir(join(projectDir, "build"), { recursive: true });
  await writeFile(join(projectDir, "build", "keep.txt"), "keep build fixture\n", "utf8");
}

async function recreateApprovalTarget(projectDir) {
  await mkdir(join(projectDir, "approval-target"), { recursive: true });
  await writeFile(join(projectDir, "approval-target", "file.txt"), "safe approval target\n", "utf8");
}

async function recreateDenyTarget(projectDir) {
  await mkdir(join(projectDir, "deny-target"), { recursive: true });
  await writeFile(join(projectDir, "deny-target", "file.txt"), "safe deny target\n", "utf8");
}

async function recreateGitMetadata(projectDir) {
  await mkdir(join(projectDir, ".git"), { recursive: true });
  await writeFile(join(projectDir, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");
}

async function recreateOutsideFiles() {
  await mkdir(OUTSIDE_READ_DIR, { recursive: true });
  await mkdir(OUTSIDE_WRITE_DIR, { recursive: true });
  await mkdir(OUTSIDE_DELETE_DIR, { recursive: true });
  await writeFile(OUTSIDE_READ_PATH, "outside fixture content should not leak\n", "utf8");
  await writeFile(OUTSIDE_WRITE_PATH, "outside original\n", "utf8");
  await writeFile(OUTSIDE_DELETE_PATH, "outside delete original\n", "utf8");
}

async function safeRm(path) {
  const absolute = resolve(path);
  if (!absolute.startsWith(FIXTURE_PREFIX)) {
    throw new Error(`Refusing to remove non-GuardMe e2e path: ${absolute}`);
  }
  await rm(absolute, { recursive: true, force: true });
}
