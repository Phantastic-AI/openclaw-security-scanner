import { existsSync, readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const ANTIVIRUS_INLINE_UNAVAILABLE_MESSAGE =
  "WARNING: Antivirus was unavailable for this action. Files created, downloaded, or installed by this action may not have been scanned for malware.";
export const ANTIVIRUS_STATUS_UNAVAILABLE_MESSAGE =
  "Antivirus: unavailable - files were not scanned";
export const ANTIVIRUS_MALWARE_QUARANTINED_MESSAGE =
  "Malware detected - file quarantined and cannot be accessed.";
export const ANTIVIRUS_ON_ACCESS_DENIED_MESSAGE =
  "Access denied - antivirus flagged this file as unsafe.";
export const ANTIVIRUS_STATUS_ACTIVE_MESSAGE =
  "Antivirus: active (on-access scanning enabled)";
export const ANTIVIRUS_STATUS_TRIGGERED_MESSAGE =
  "Antivirus: active (triggered scans via clamd)";

const DEFAULT_CLAMD_SOCKET_CANDIDATES = [
  "/run/clamav/clamd.ctl",
  "/var/run/clamav/clamd.ctl",
  "/tmp/clamd.sock",
];

const DEFAULT_CLAMD_CONFIG_CANDIDATES = [
  "/etc/clamav/clamd.conf",
  "/usr/local/etc/clamd.conf",
];

const COMMAND_WITH_VALUE_FLAGS = new Set([
  "-b",
  "--branch",
  "--origin",
  "--template",
  "--config",
  "-C",
  "-c",
  "-o",
  "--output",
  "-P",
  "--directory-prefix",
  "--output-dir",
  "-O",
  "-d",
]);

function normalizeMode(value) {
  const normalized = String(value || "auto").trim().toLowerCase();
  if (normalized === "disabled" || normalized === "required") {
    return normalized;
  }
  return "auto";
}

export function normalizeAntivirusConfig(raw = {}) {
  return {
    mode: normalizeMode(raw.antivirusMode),
    warnUnavailable: raw.antivirusWarnUnavailable !== false,
    socketPath: String(raw.antivirusSocketPath || "").trim() || undefined,
    clamdConfigPath: String(raw.antivirusClamdConfigPath || "").trim() || undefined,
    scanTimeoutMs:
      Number.isFinite(raw.antivirusScanTimeoutMs) && raw.antivirusScanTimeoutMs > 0
        ? Math.trunc(Number(raw.antivirusScanTimeoutMs))
        : 4000,
  };
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function normalizePathCandidate(baseDir, candidate) {
  const raw = String(candidate || "").trim();
  if (!raw || raw === "-") {
    return undefined;
  }
  if (/^[a-z]+:\/\//i.test(raw)) {
    return undefined;
  }
  if (path.isAbsolute(raw)) {
    return path.normalize(raw);
  }
  if (!baseDir) {
    return undefined;
  }
  return path.normalize(path.resolve(baseDir, raw));
}

function basenameFromRepo(repo) {
  const raw = String(repo || "").trim().replace(/[\\\/]+$/, "");
  if (!raw) {
    return undefined;
  }
  const slash = raw.split(/[/:]/).pop() || "";
  return slash.replace(/\.git$/i, "").trim() || undefined;
}

function deriveShellBaseDir(commandText, fallbackBaseDir) {
  const matches = Array.from(String(commandText || "").matchAll(/(?:^|&&|;)\s*cd\s+((?:"[^"]+"|'[^']+'|[^\s&;]+))/g));
  if (matches.length === 0) {
    return fallbackBaseDir;
  }
  const candidate = matches[matches.length - 1]?.[1];
  return normalizePathCandidate(
    fallbackBaseDir || process.cwd(),
    String(candidate || "").replace(/^['"]|['"]$/g, ""),
  );
}

function shellSplit(commandText) {
  const text = String(commandText || "");
  const tokens = [];
  let current = "";
  let quote = null;
  let escaped = false;
  for (const char of text) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current) {
    tokens.push(current);
  }
  return tokens;
}

function deriveGitCloneRoots(tokens, baseDir) {
  let repo;
  let destination;
  let skipNext = false;
  const cloneIndex = tokens.findIndex((token) => token === "clone");
  const args = cloneIndex >= 0 ? tokens.slice(cloneIndex + 1) : [];
  const positional = [];
  for (const token of args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (COMMAND_WITH_VALUE_FLAGS.has(token)) {
      skipNext = true;
      continue;
    }
    if (token.startsWith("-")) {
      continue;
    }
    positional.push(token);
  }
  repo = positional[0];
  destination = positional[1] || basenameFromRepo(repo);
  return unique([
    normalizePathCandidate(baseDir, destination),
    normalizePathCandidate(baseDir, "."),
  ]);
}

function deriveDownloadRoots(tokens, baseDir) {
  let output;
  let outputDir;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const next = tokens[index + 1];
    if (token === "-o" || token === "--output") {
      output = next;
      index += 1;
      continue;
    }
    if (token === "-P" || token === "--directory-prefix" || token === "--output-dir") {
      outputDir = next;
      index += 1;
      continue;
    }
    if (token === "-O" || token === "--remote-name") {
      outputDir = baseDir || ".";
      continue;
    }
  }
  return unique([
    normalizePathCandidate(baseDir, output),
    normalizePathCandidate(baseDir, outputDir),
    normalizePathCandidate(baseDir, "."),
  ]);
}

function deriveArchiveRoots(tokens, baseDir) {
  let targetDir;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === "-C" || token === "-d") {
      targetDir = tokens[index + 1];
      index += 1;
    }
  }
  return unique([
    normalizePathCandidate(baseDir, targetDir),
    normalizePathCandidate(baseDir, "."),
  ]);
}

function buildActionSummary(action) {
  if (!action) {
    return "recent file action";
  }
  const directory = action.roots?.[0];
  if (directory) {
    return `${action.kind} in ${directory}`;
  }
  return action.kind;
}

export function analyzeAntivirusAction({ params = {}, evaluation = {} } = {}) {
  if (evaluation?.capability !== "shell_exec") {
    return undefined;
  }
  const commandText = String(params?.cmd || params?.command || evaluation?.paramText || "").trim();
  if (!commandText) {
    return undefined;
  }
  const normalizedCommand = commandText.toLowerCase();
  const configuredBaseDir = normalizePathCandidate(
    process.cwd(),
    String(params?.workdir || params?.cwd || "").trim() || ".",
  );
  const baseDir = deriveShellBaseDir(commandText, configuredBaseDir);
  const tokens = shellSplit(commandText);

  if (/\bgit\s+clone\b/.test(normalizedCommand)) {
    return {
      kind: "git clone",
      commandText,
      roots: deriveGitCloneRoots(tokens, baseDir),
    };
  }
  if (/\b(?:npm|pnpm|yarn|bun)\s+(?:install|add|ci)\b/.test(normalizedCommand)) {
    return {
      kind: "package install",
      commandText,
      roots: unique([normalizePathCandidate(baseDir, ".")]),
    };
  }
  if (/\b(?:pip|pip3)\s+install\b/.test(normalizedCommand) || /\buv\s+pip\s+install\b/.test(normalizedCommand)) {
    return {
      kind: "python package install",
      commandText,
      roots: unique([normalizePathCandidate(baseDir, ".")]),
    };
  }
  if (/\bcargo\s+install\b/.test(normalizedCommand)) {
    return {
      kind: "cargo install",
      commandText,
      roots: unique([normalizePathCandidate(baseDir, "."), normalizePathCandidate(baseDir, process.env.CARGO_HOME)]),
    };
  }
  if (/\bgo\s+(?:get|install)\b/.test(normalizedCommand)) {
    return {
      kind: "go install",
      commandText,
      roots: unique([normalizePathCandidate(baseDir, "."), normalizePathCandidate(baseDir, process.env.GOBIN)]),
    };
  }
  if (/\b(?:curl|wget)\b/.test(normalizedCommand)) {
    return {
      kind: "download",
      commandText,
      roots: deriveDownloadRoots(tokens, baseDir),
    };
  }
  if (/\btar\b/.test(normalizedCommand) || /\bunzip\b/.test(normalizedCommand)) {
    return {
      kind: "archive extract",
      commandText,
      roots: deriveArchiveRoots(tokens, baseDir),
    };
  }
  return undefined;
}

async function pathExists(filePath) {
  try {
    await fs.stat(filePath);
    return true;
  } catch {
    return false;
  }
}

function pathExistsSync(filePath) {
  try {
    return existsSync(filePath);
  } catch {
    return false;
  }
}

function resolveExistingPathSync(firstChoice, fallbacks = []) {
  if (firstChoice && pathExistsSync(firstChoice)) {
    return firstChoice;
  }
  for (const candidate of fallbacks) {
    if (candidate && pathExistsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

async function resolveExistingPath(firstChoice, fallbacks = []) {
  if (firstChoice && (await pathExists(firstChoice))) {
    return firstChoice;
  }
  for (const candidate of fallbacks) {
    if (candidate && (await pathExists(candidate))) {
      return candidate;
    }
  }
  return undefined;
}

async function loadOnAccessRoots(configPath) {
  if (!configPath) {
    return [];
  }
  try {
    const raw = await fs.readFile(configPath, "utf8");
    return unique(
      raw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"))
        .map((line) => line.match(/^OnAccessIncludePath\s+(.+)$/i)?.[1])
        .filter(Boolean)
        .map((value) => String(value).replace(/^['"]|['"]$/g, "").trim())
        .filter(Boolean)
        .map((value) => path.normalize(value)),
    );
  } catch {
    return [];
  }
}

function loadOnAccessRootsSync(configPath) {
  if (!configPath) {
    return [];
  }
  try {
    const raw = readFileSync(configPath, "utf8");
    return unique(
      raw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"))
        .map((line) => line.match(/^OnAccessIncludePath\s+(.+)$/i)?.[1])
        .filter(Boolean)
        .map((value) => String(value).replace(/^['"]|['"]$/g, "").trim())
        .filter(Boolean)
        .map((value) => path.normalize(value)),
    );
  } catch {
    return [];
  }
}

async function isProcessRunning(commandName) {
  try {
    await execFileAsync("pgrep", ["-x", commandName]);
    return true;
  } catch {
    return false;
  }
}

function pathCoveredByRoot(targetPath, rootPath) {
  const target = path.normalize(targetPath);
  const root = path.normalize(rootPath);
  return target === root || target.startsWith(`${root}${path.sep}`);
}

function createSocketRequest(socketPath, command, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let output = "";
    const socket = net.createConnection(socketPath);
    const finish = (fn, value) => {
      if (settled) {
        return;
      }
      settled = true;
      fn(value);
    };
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish(reject, new Error(`clamd request timed out for ${command}`));
    });
    socket.on("error", (error) => finish(reject, error));
    socket.on("data", (chunk) => {
      output += chunk.toString("utf8");
    });
    socket.on("end", () => finish(resolve, output.trim()));
    socket.on("close", () => finish(resolve, output.trim()));
    socket.on("connect", () => {
      socket.write(`n${command}\n`);
      socket.end();
    });
  });
}

async function pingClamd(socketPath, timeoutMs) {
  try {
    const response = await createSocketRequest(socketPath, "PING", timeoutMs);
    return typeof response === "string" && response.toUpperCase().includes("PONG");
  } catch {
    return false;
  }
}

function parseScanResponse(output, targetPath) {
  const lines = String(output || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const findings = [];
  const errors = [];
  let scanned = false;
  for (const line of lines) {
    const [, reportedPath = targetPath, detail = line] = line.match(/^(.*?):\s+(.*)$/) || [];
    if (detail === "OK") {
      scanned = true;
      continue;
    }
    if (detail.endsWith("FOUND")) {
      scanned = true;
      findings.push({
        path: reportedPath,
        signature: detail.slice(0, -5).trim(),
      });
      continue;
    }
    errors.push({ path: reportedPath, detail });
  }
  if (findings.length > 0) {
    return {
      verdict: "infected",
      findings,
      errors,
      scanned,
    };
  }
  if (errors.length > 0) {
    return {
      verdict: scanned ? "partial_error" : "error",
      findings,
      errors,
      scanned,
    };
  }
  return {
    verdict: scanned ? "clean" : "error",
    findings,
    errors,
    scanned,
  };
}

export async function detectAntivirusBackend(config, targetPaths = []) {
  const normalizedTargets = unique(targetPaths.map((value) => String(value || "").trim())).filter(Boolean);
  if (config.mode === "disabled") {
    return {
      status: "disabled",
      protection: "disabled",
      warnUnavailable: false,
      targetPaths: normalizedTargets,
      onAccessRoots: [],
      coveredPaths: [],
    };
  }

  const socketPath = await resolveExistingPath(config.socketPath, DEFAULT_CLAMD_SOCKET_CANDIDATES);
  const clamdConfigPath = await resolveExistingPath(
    config.clamdConfigPath,
    DEFAULT_CLAMD_CONFIG_CANDIDATES,
  );
  const onAccessRoots = await loadOnAccessRoots(clamdConfigPath);
  const coveredPaths = normalizedTargets.filter((candidate) =>
    onAccessRoots.some((root) => pathCoveredByRoot(candidate, root)),
  );
  const clamonaccRunning = onAccessRoots.length > 0 ? await isProcessRunning("clamonacc") : false;
  const clamdHealthy = socketPath ? await pingClamd(socketPath, config.scanTimeoutMs) : false;

  if (clamdHealthy && clamonaccRunning && (normalizedTargets.length === 0 || coveredPaths.length > 0)) {
    return {
      status: "active",
      protection: "on-access",
      socketPath,
      clamdConfigPath,
      onAccessRoots,
      coveredPaths,
      clamonaccRunning,
      targetPaths: normalizedTargets,
      warnUnavailable: false,
      statusMessage: ANTIVIRUS_STATUS_ACTIVE_MESSAGE,
    };
  }

  if (clamdHealthy) {
    return {
      status: "active",
      protection: "triggered",
      socketPath,
      clamdConfigPath,
      onAccessRoots,
      coveredPaths,
      clamonaccRunning,
      targetPaths: normalizedTargets,
      warnUnavailable: false,
      statusMessage: ANTIVIRUS_STATUS_TRIGGERED_MESSAGE,
    };
  }

  return {
    status: "unavailable",
    protection: "unavailable",
    socketPath,
    clamdConfigPath,
    onAccessRoots,
    coveredPaths,
    clamonaccRunning,
    targetPaths: normalizedTargets,
    warnUnavailable: config.warnUnavailable,
    statusMessage: ANTIVIRUS_STATUS_UNAVAILABLE_MESSAGE,
  };
}

export function resolveImmediateAntivirusWarning(config, targetPaths = []) {
  const normalizedTargets = unique(targetPaths.map((value) => String(value || "").trim())).filter(Boolean);
  if (config.mode === "disabled" || config.warnUnavailable === false) {
    return undefined;
  }
  const socketPath = resolveExistingPathSync(config.socketPath, DEFAULT_CLAMD_SOCKET_CANDIDATES);
  const clamdConfigPath = resolveExistingPathSync(
    config.clamdConfigPath,
    DEFAULT_CLAMD_CONFIG_CANDIDATES,
  );
  const onAccessRoots = loadOnAccessRootsSync(clamdConfigPath);
  const coveredPaths = normalizedTargets.filter((candidate) =>
    onAccessRoots.some((root) => pathCoveredByRoot(candidate, root)),
  );
  if (socketPath) {
    return undefined;
  }
  if (onAccessRoots.length > 0 && coveredPaths.length > 0) {
    return undefined;
  }
  return ANTIVIRUS_INLINE_UNAVAILABLE_MESSAGE;
}

export async function runTriggeredClamdScan(backend, targetPaths = []) {
  const normalizedTargets = unique(targetPaths.map((value) => String(value || "").trim())).filter(Boolean);
  const existingTargets = [];
  for (const candidate of normalizedTargets) {
    if (await pathExists(candidate)) {
      existingTargets.push(candidate);
    }
  }
  if (!backend?.socketPath || existingTargets.length === 0) {
    return {
      verdict: "skipped",
      scannedPaths: [],
      findings: [],
      errors: existingTargets.length === 0 ? [{ detail: "no existing scan roots" }] : [],
    };
  }

  const results = [];
  for (const targetPath of existingTargets) {
    try {
      const output = await createSocketRequest(
        backend.socketPath,
        `SCAN ${targetPath}`,
        backend.scanTimeoutMs || 4000,
      );
      results.push({
        path: targetPath,
        ...parseScanResponse(output, targetPath),
      });
    } catch (error) {
      results.push({
        path: targetPath,
        verdict: "error",
        findings: [],
        errors: [{ detail: String(error) }],
        scanned: false,
      });
    }
  }

  const findings = results.flatMap((result) =>
    result.findings.map((entry) => ({
      ...entry,
      rootPath: result.path,
    })),
  );
  const errors = results.flatMap((result) =>
    result.errors.map((entry) => ({
      ...entry,
      rootPath: result.path,
    })),
  );
  if (findings.length > 0) {
    return {
      verdict: "infected",
      scannedPaths: existingTargets,
      findings,
      errors,
    };
  }
  if (errors.length > 0) {
    return {
      verdict: "error",
      scannedPaths: existingTargets,
      findings,
      errors,
    };
  }
  return {
    verdict: "clean",
    scannedPaths: existingTargets,
    findings,
    errors,
  };
}

export function buildAntivirusNotice(outcome) {
  if (!outcome) {
    return undefined;
  }
  if (outcome.verdict === "unavailable") {
    return {
      severity: "warn",
      message: ANTIVIRUS_INLINE_UNAVAILABLE_MESSAGE,
      actionSummary: buildActionSummary(outcome.action),
    };
  }
  if (outcome.verdict === "infected") {
    return {
      severity: "warn",
      message: ANTIVIRUS_MALWARE_QUARANTINED_MESSAGE,
      actionSummary: buildActionSummary(outcome.action),
    };
  }
  return undefined;
}

export function buildAntivirusPrependContext(notices = []) {
  const resolved = Array.isArray(notices) ? notices.filter(Boolean) : [];
  if (resolved.length === 0) {
    return "";
  }
  const lines = [
    `${resolved.length === 1 ? REVIEW_LABEL_SINGULAR : REVIEW_LABEL_PLURAL}`,
    "System instruction: the next assistant reply is invalid unless line 1 is exactly the required antivirus warning line below.",
    "System instruction: put that exact warning line first, on its own line, before any markdown, bullets, or summary, even if the command succeeded.",
    "System instruction: do not omit, paraphrase, soften, or contradict this warning.",
    'System instruction: do not say that no antivirus warning was surfaced when the warning line below is present.',
    "System instruction: after the required warning line, you may briefly summarize the command result.",
  ];
  for (const notice of resolved) {
    lines.push(`Required opening warning line: ${notice.message}`);
    lines.push(`Antivirus warning to surface verbatim: ${notice.message}`);
    if (notice.actionSummary) {
      lines.push(`Affected action: ${notice.actionSummary}`);
    }
  }
  return lines.join("\n");
}

const REVIEW_LABEL_SINGULAR =
  "OpenClaw Scanner recorded an antivirus warning for a recent file action.";
const REVIEW_LABEL_PLURAL =
  "OpenClaw Scanner recorded antivirus warnings for recent file actions.";
