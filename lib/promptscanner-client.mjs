export async function scanWithPromptScanner(params) {
  const response = await fetch(`${params.apiUrl.replace(/\/$/, "")}/v1/scan`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${params.apiKey}`,
    },
    body: JSON.stringify({
      text: params.text,
      caller_id: params.callerId,
      request_id: params.requestId,
      labels: params.labels,
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`PromptScanner request failed (${response.status}): ${text}`);
  }

  return await response.json();
}

export async function reviewIngressWithPromptScanner(params) {
  const result = await scanWithPromptScanner(params);
  return {
    finalAction: result?.verdict === "injection" ? "quarantine" : "allow",
    reasonCode: result?.verdict === "injection" ? "promptscanner_injection" : "promptscanner_safe",
    reason: result?.verdict === "injection" ? "PromptScanner flagged the tool output." : "",
    confidence:
      Number.isFinite(Number(result?.confidence)) && Number(result.confidence) >= 0
        ? Math.max(0, Math.min(1, Number(result.confidence)))
        : undefined,
    scanId: typeof result?.scan_id === "string" ? result.scan_id : undefined,
    model: typeof result?.model === "string" ? result.model : undefined,
  };
}
