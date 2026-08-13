const crypto = require("crypto");
const { parseHeader, splitRawEmail } = require("./headerParser");
const { extractSender } = require("./senderExtractor");
const { extractIPs } = require("./ipExtractor");
const { analyzeRouting } = require("./routingAnalyzer");
const { performAuthentication } = require("./authenticationEngine");
const { detectFindings } = require("./suspiciousHeaderDetector");
const { calculateRiskScore } = require("./riskCalculator");
const { classifyThreat } = require("./threatClassifier");

async function generateForensicReport(input) {
  let header = input.header || "";
  let body = input.body || "";

  if (input.rawEmail) {
    const split = splitRawEmail(input.rawEmail);
    header = split.header;
    body = split.body;
  }

  if (!header.trim()) {
    throw new Error("Email header is empty.");
  }

  // IMPORTANT:
  // DKIM cryptographic verification needs the exact original message,
  // including the body. If only a header is supplied, DKIM cannot be
  // cryptographically verified.
  const message = `${header}\r\n\r\n${body}`;

  const parsed = parseHeader(header);
  const sender = extractSender(parsed);
  const ips = extractIPs(header);
  const routing = analyzeRouting(parsed);

  const authentication = await performAuthentication(message, {
    clientIp: input.clientIp,
    helo: input.helo,
    sender: input.sender || sender.returnPath,
    trustReceived: !input.clientIp && !input.helo && !input.sender
  });

  const findings = detectFindings({
    sender,
    routing,
    authentication,
    parsed
  });

  const riskScore = calculateRiskScore(authentication, findings);
  const threat = classifyThreat(riskScore);

  return {
    reportMetadata: {
      reportId: crypto.randomUUID(),
      generatedAt: new Date().toISOString(),
      engine: "Email Header Forensic Engine",
      phase: "Phase 3 v2",
      version: "2.0.0"
    },

    verificationMode: {
      spf: "REAL_DNS_VERIFICATION",
      dkim: body
        ? "REAL_CRYPTOGRAPHIC_DNS_VERIFICATION"
        : "NOT_COMPLETE_WITHOUT_MESSAGE_BODY",
      dmarc: "REAL_DNS_POLICY_AND_ALIGNMENT_VERIFICATION",
      dnsAccessRequired: true
    },

    inputSummary: {
      headerLength: header.length,
      bodyLength: body.length,
      completeMessageProvided: Boolean(input.rawEmail) || Boolean(body),
      sha256: crypto.createHash("sha256").update(message).digest("hex")
    },

    senderAnalysis: sender,

    ipAnalysis: {
      ...ips,
      verificationIpUsed: input.clientIp || "derived from trusted Received chain when available"
    },

    routingAnalysis: routing,

    authenticationAnalysis: authentication,verificationSummary: {
  spf: {
    result:
      authentication.spf?.result ||
      "not_available",

    verifiedIp:
      authentication.spf?.ip ||
      null,

    mailFrom:
      authentication.spf?.mailFrom ||
      authentication.spf?.domain ||
      null,

    helo:
      authentication.spf?.helo ||
      null
  },

  dkim: {
    result:
      authentication.dkim?.result ||
      "not_available",

    cryptographicPass:
      authentication.dkim?.cryptographicPass ||
      false,

    signatures:
      authentication.dkim?.results ||
      []
  },

  dmarc: {
    result:
      authentication.dmarc?.result ||
      "not_available",

    policy:
      authentication.dmarc?.policy ||
      null,

    fromDomain:
      authentication.dmarc?.fromDomain ||
      null
  }
},

    suspiciousFindings: findings,

    riskAssessment: {
      riskScore,
      ...threat
    },

    forensicConclusion:
      riskScore >= 70
        ? "High-risk indicators detected. Preserve the original email and investigate the authentication and routing evidence."
        : riskScore >= 40
          ? "Authentication or header anomalies were detected. Further forensic review is recommended."
          : "No major anomaly was detected by the configured authentication checks."
  };
}

module.exports = { generateForensicReport };
