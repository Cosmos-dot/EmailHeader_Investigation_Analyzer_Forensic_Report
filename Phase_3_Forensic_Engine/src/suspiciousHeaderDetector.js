function getResult(section) {
  return section?.result || null;
}

function detectFindings({ sender, routing, authentication, parsed }) {
  const findings = [];

  const spf = getResult(authentication.spf);
  const dkim = getResult(authentication.dkim);
  const dmarc = getResult(authentication.dmarc);

  if (!parsed.byName["from"]) {
    findings.push({ code: "MISSING_FROM", severity: "high", message: "From header is missing." });
  }

  if (!parsed.byName["date"]) {
    findings.push({ code: "MISSING_DATE", severity: "low", message: "Date header is missing." });
  }

  if (!parsed.byName["message-id"]) {
    findings.push({ code: "MISSING_MESSAGE_ID", severity: "low", message: "Message-ID header is missing." });
  }

  if (spf && ["fail", "softfail", "permerror"].includes(spf)) {
    findings.push({ code: "SPF_FAILURE", severity: "high", message: `Actual SPF verification returned ${spf}.` });
  }

  if (dkim && ["fail", "neutral", "temperror", "permerror", "policy"].includes(dkim)) {
    findings.push({ code: "DKIM_FAILURE", severity: "high", message: `Actual DKIM verification returned ${dkim}.` });
  }

  if (dmarc && ["fail", "permerror", "temperror"].includes(dmarc)) {
    findings.push({ code: "DMARC_FAILURE", severity: "high", message: `Actual DMARC verification returned ${dmarc}.` });
  }

  if (sender.fromDomain && sender.returnPathDomain &&
      sender.fromDomain !== sender.returnPathDomain) {
    findings.push({
      code: "FROM_RETURN_PATH_MISMATCH",
      severity: "medium",
      message: "From domain and Return-Path domain differ. DMARC alignment is evaluated separately."
    });
  }

  if (routing.hopCount === 0) {
    findings.push({
      code: "NO_RECEIVED_HEADERS",
      severity: "medium",
      message: "No Received headers were found."
    });
  }

  return findings;
}

module.exports = { detectFindings };
