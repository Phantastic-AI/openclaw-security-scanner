import { createHash } from "node:crypto";

export function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

export function hashText(text) {
  return createHash("sha256").update(text).digest("hex");
}

function pushString(parts, value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (trimmed) {
    parts.push(trimmed);
  }
}

function collectStrings(value, parts, depth = 0) {
  if (value == null || depth > 5) {
    return;
  }
  if (typeof value === "string") {
    pushString(parts, value);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    parts.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, parts, depth + 1);
    }
    return;
  }
  if (typeof value === "object") {
    if (typeof value.text === "string") {
      pushString(parts, value.text);
    }
    if (typeof value.output_text === "string") {
      pushString(parts, value.output_text);
    }
    for (const [key, nested] of Object.entries(value)) {
      if (key === "text" || key === "output_text") {
        continue;
      }
      collectStrings(nested, parts, depth + 1);
    }
  }
}

export function extractToolResultText(value, maxChars = 24000) {
  const parts = [];
  collectStrings(value, parts, 0);
  const text = parts.join("\n").trim();
  if (!text) {
    return "";
  }
  if (text.length <= maxChars) {
    return text;
  }
  return `${text.slice(0, maxChars)}\n[truncated ${text.length - maxChars} chars]`;
}

export function extractAssistantToolCalls(messages) {
  const map = new Map();
  for (const message of messages || []) {
    if (!message || message.role !== "assistant") {
      continue;
    }
    const content = Array.isArray(message.content) ? message.content : [];
    for (const part of content) {
      if (part?.type === "toolCall" && typeof part.id === "string" && typeof part.name === "string") {
        map.set(part.id, part.name);
      }
    }
  }
  return map;
}

export function buildToolSignature(toolName, params) {
  return `${toolName || "unknown"}:${hashText(stableStringify(params || {}))}`;
}

export function sanitizeCallerId(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._:-]/g, "-");
}
