#!/usr/bin/env node
import { spawn } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, mkdir } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const coverageDirectory = resolve(projectRoot, "coverage");
const lcovFile = resolve(coverageDirectory, "lcov.info");

const coverageArgs = [
  "--test",
  "--test-reporter=lcov",
  `--test-reporter-destination=${lcovFile}`,
  "--experimental-test-coverage",
  "--test-coverage-include=src/**/*.ts",
  "--test-coverage-exclude=test/**",
  "test/*.test.mjs",
];

async function runCoverage() {
  await mkdir(coverageDirectory, { recursive: true });

  const exitCode = await runNodeTestsWithCoverage();
  if (exitCode !== 0) {
    process.exitCode = exitCode;
    return;
  }

  await access(lcovFile, fsConstants.R_OK);
  console.log(`Coverage report written to ${relative(projectRoot, lcovFile)}`);
}

function runNodeTestsWithCoverage() {
  return new Promise((resolveExitCode) => {
    const child = spawn(process.execPath, coverageArgs, {
      cwd: projectRoot,
      stdio: "inherit",
      shell: false,
    });

    child.once("error", (error) => {
      console.error(`Failed to start coverage runner: ${error.message}`);
      resolveExitCode(1);
    });

    child.once("exit", (code, signal) => {
      if (signal) {
        console.error(`Coverage runner stopped by signal ${signal}`);
        resolveExitCode(1);
        return;
      }

      resolveExitCode(code ?? 1);
    });
  });
}

try {
  await runCoverage();
} catch (error) {
  console.error(`Coverage run failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
