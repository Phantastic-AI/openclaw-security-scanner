#!/usr/bin/env node

import {
  DEFAULT_REVIEW_LEDGER_LIMIT,
  defaultReviewLedgerStateDir,
  normalizeReviewLedgerLimit,
  printReviewLedgerReport,
} from "../lib/review-ledger-report.mjs";

function usage() {
  console.error(
    "usage: node scripts/print_review_ledger.mjs [--json] [--state-dir <dir>] [--limit <n>]",
  );
  process.exit(1);
}

async function main() {
  const args = process.argv.slice(2);
  let json = false;
  let limit = DEFAULT_REVIEW_LEDGER_LIMIT;
  let stateDir = defaultReviewLedgerStateDir();

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      json = true;
      continue;
    }
    if (arg === "--state-dir") {
      index += 1;
      if (index >= args.length) {
        usage();
      }
      stateDir = args[index];
      continue;
    }
    if (arg === "--limit") {
      index += 1;
      if (index >= args.length) {
        usage();
      }
      try {
        limit = normalizeReviewLedgerLimit(args[index]);
      } catch {
        usage();
      }
      continue;
    }
    usage();
  }

  await printReviewLedgerReport({ stateDir, limit, json });
}

main().catch((error) => {
  console.error(String(error));
  process.exit(1);
});
