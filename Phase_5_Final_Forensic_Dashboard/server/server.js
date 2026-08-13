import "dotenv/config";
import express from "express";
import cors from "cors";
import multer from "multer";
import { authenticate } from "@forwardemail/mailauth";
import tldts from "tldts";

const app = express();
const PORT = 5001;

app.use(cors());
app.use(express.json({ limit: "10mb" }));

// ===========================================================
// FILE UPLOAD
// ===========================================================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

// ===========================================================
// UTILITY FUNCTIONS
// ===========================================================

function normalizeDomain(domain) {
  if (!domain) {
    return null;
  }

  return domain
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

function extractEmailDomain(email) {
  if (!email || !email.includes("@")) {
    return null;
  }

  return normalizeDomain(
    email.substring(email.lastIndexOf("@") + 1)
  );
}

function getDomain(value) {
  const normalized = normalizeDomain(value);

  if (!normalized) {
    return null;
  }

  try {
    const domain = tldts.getDomain(normalized);

    if (domain) {
      return normalizeDomain(domain);
    }
  } catch (error) {
    // Fall back to simple extraction
  }

  const parts = normalized.split(".");

  if (parts.length < 2) {
    return normalized;
  }

  return parts.slice(-2).join(".");
}
// ===========================================================
// GENERIC HEADER EXTRACTION
// ===========================================================

function extractHeader(rawEmail, headerName) {
  const text = rawEmail.toString("utf8").replace(/^\uFEFF/, "");

  const regex = new RegExp(
    "^" +
      headerName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
      ":\\s*(.*(?:\\r?\\n[ \\t]+.*)*)",
    "gmi"
  );

  const match = regex.exec(text);

  if (!match) {
    return null;
  }

  return match[1]
    .replace(/\r?\n[ \t]+/g, " ")
    .trim();
}

// ===========================================================
// HEADER FROM
// ===========================================================

function extractHeaderFrom(rawEmail) {
  const value = extractHeader(
    rawEmail,
    "From"
  );

  if (!value) {
    return null;
  }

  const angleMatch = value.match(
    /<([^<>@\s]+@[^<>@\s]+)>/
  );

  if (angleMatch) {
    return angleMatch[1]
      .trim()
      .toLowerCase();
  }

  const emailMatch = value.match(
    /([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i
  );

  return emailMatch
    ? emailMatch[1].trim().toLowerCase()
    : null;
}

// ===========================================================
// ENVELOPE / RETURN-PATH
// ===========================================================

function extractEnvelopeSender(rawEmail) {
  const value =
    extractHeader(rawEmail, "Return-Path");

  if (!value) {
    return null;
  }

  // Return-Path normally looks like:
  // Return-Path: <sender@example.com>

  const angleMatch = value.match(
    /<([^<>@\s]+@[^<>@\s]+)>/
  );

  if (angleMatch) {
    return angleMatch[1]
      .trim()
      .toLowerCase();
  }

  const emailMatch = value.match(
    /([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i
  );

  return emailMatch
    ? emailMatch[1].trim().toLowerCase()
    : null;
}

// ===========================================================
// RECEIVED / SMTP INFORMATION
// ===========================================================

function extractSMTPInfo(rawEmail) {
  const text = rawEmail.toString("utf8");

  const receivedHeaders = [];

  // Extract all Received headers, including folded lines
  const regex =
    /^Received:\s*(.*(?:\r?\n[ \t]+.*)*)/gmi;

  let match;

  while ((match = regex.exec(text)) !== null) {
    receivedHeaders.push(
      match[1]
        .replace(/\r?\n[ \t]+/g, " ")
        .trim()
    );
  }

  if (receivedHeaders.length === 0) {
    return {
      ip: null,
      helo: null,
      received: null,
      hops: 0
    };
  }

  // The last Received header is normally the earliest
  // hop in the message's Received chain.
  const candidate =
    receivedHeaders[
      receivedHeaders.length - 1
    ];

  // IPv4 or IPv6 inside [ ... ]
  const bracketIpMatch =
    candidate.match(
      /\[([0-9a-fA-F:.]+)\]/
    );

  // Fallback for unbracketed IPv4
  const ipv4Match =
    candidate.match(
      /\b((?:\d{1,3}\.){3}\d{1,3})\b/
    );

  const ip =
    bracketIpMatch
      ? bracketIpMatch[1]
      : ipv4Match
      ? ipv4Match[1]
      : null;

  // Extract hostname after "from"
  const fromMatch =
    candidate.match(
      /^from\s+([^\s(]+)/
    );

  const helo =
    fromMatch
      ? fromMatch[1]
      : null;

  return {
    ip,
    helo,
    received: candidate,
    hops: receivedHeaders.length,
    allReceived: receivedHeaders
  };
}

// ===========================================================
// DKIM HEADER PARSING
// ===========================================================

function extractDKIMHeaders(rawEmail) {
  const text = rawEmail.toString("utf8");

  const signatures = [];

  // DKIM-Signature can be folded across multiple lines
  const regex =
    /^DKIM-Signature:\s*(.*(?:\r?\n[ \t]+.*)*)/gmi;

  let match;

  while ((match = regex.exec(text)) !== null) {
    const value = match[1]
      .replace(/\r?\n[ \t]+/g, " ")
      .trim();

    const tags = {};

    value.split(";").forEach((part) => {
      const separator =
        part.indexOf("=");

      if (separator === -1) {
        return;
      }

      const key =
        part
          .slice(0, separator)
          .trim()
          .toLowerCase();

      const val =
        part
          .slice(separator + 1)
          .trim();

      tags[key] = val;
    });

    signatures.push({
      domain: normalizeDomain(
        tags.d || null
      ),
      selector:
        tags.s || null,
      identity:
        tags.i || null,
      algorithm:
        tags.a || null
    });
  }

  return signatures;
}

// ===========================================================
// DOMAIN ALIGNMENT
// ===========================================================

function domainsAlign(
  identifierDomain,
  fromDomain,
  strict = false
) {
  const identifier =
    normalizeDomain(identifierDomain);

  const from =
    normalizeDomain(fromDomain);

  if (!identifier || !from) {
    return false;
  }

  if (strict) {
    return identifier === from;
  }

  const identifierOrg =
    getDomain(identifier);

  const fromOrg =
    getDomain(from);

  if (!identifierOrg || !fromOrg) {
    return identifier === from;
  }

  return (
    identifierOrg.toLowerCase() ===
    fromOrg.toLowerCase()
  );
}

// ===========================================================
// EXPLICIT DMARC ALIGNMENT
// ===========================================================

function calculateDMARCAlignment({
  fromDomain,
  envelopeSenderDomain,
  dkimResults,
  dmarcResult
}) {
  // Default DMARC alignment mode is relaxed
  const dmarcAlignment =
    dmarcResult?.alignment || {};

  const spfStrict =
    Boolean(
      dmarcAlignment?.spf?.strict
    );

  const dkimStrict =
    Boolean(
      dmarcAlignment?.dkim?.strict
    );

  // ---------------------------------------------------------
  // SPF ALIGNMENT
  // ---------------------------------------------------------

  const spfAligned =
    domainsAlign(
      envelopeSenderDomain,
      fromDomain,
      spfStrict
    );

  // SPF authentication must also PASS
  const spfAuthenticationResult =
    dmarcResult?.spf?.result ||
    null;

  const spfAuthenticated =
    String(
      spfAuthenticationResult
    ).toLowerCase() === "pass";

  const spfDMARCAligned =
    spfAuthenticated &&
    spfAligned;

  // ---------------------------------------------------------
  // DKIM ALIGNMENT
  // ---------------------------------------------------------

  const dkimCandidates = [];

  if (Array.isArray(dkimResults)) {
    for (const result of dkimResults) {
      const signingDomain =
        normalizeDomain(
          result?.signingDomain ||
          result?.domain ||
          result?.header?.d ||
          result?.header?.domain ||
          null
        );

      const authenticationResult =
        String(
          result?.status?.result ||
          result?.result ||
          ""
        ).toLowerCase();

      if (!signingDomain) {
        continue;
      }

      const aligned =
        domainsAlign(
          signingDomain,
          fromDomain,
          dkimStrict
        );

      const authenticated =
        authenticationResult === "pass";

      dkimCandidates.push({
        signingDomain,
        authenticated,
        authenticationResult,
        aligned,
        dmarcAligned:
          authenticated && aligned
      });
    }
  }

  const dkimDMARCAligned =
    dkimCandidates.some(
      (candidate) =>
        candidate.dmarcAligned === true
    );

  // ---------------------------------------------------------
  // FINAL DMARC CALCULATION
  // ---------------------------------------------------------

  const calculatedDMARCPass =
    spfDMARCAligned ||
    dkimDMARCAligned;

  let passedBy = "none";

  if (
    spfDMARCAligned &&
    dkimDMARCAligned
  ) {
    passedBy = "spf+dkim";
  } else if (spfDMARCAligned) {
    passedBy = "spf";
  } else if (dkimDMARCAligned) {
    passedBy = "dkim";
  }

  return {
    fromDomain,
    envelopeSenderDomain,

    alignmentMode: {
      spf:
        spfStrict
          ? "strict"
          : "relaxed",

      dkim:
        dkimStrict
          ? "strict"
          : "relaxed"
    },

    spf: {
      authenticated:
        spfAuthenticated,

      authenticationResult:
        spfAuthenticationResult,

      aligned:
        spfAligned,

      dmarcAligned:
        spfDMARCAligned
    },

    dkim: {
      signatures:
        dkimCandidates,

      aligned:
        dkimDMARCAligned
    },

    dmarc: {
      calculatedResult:
        calculatedDMARCPass
          ? "pass"
          : "fail",

      passedBy
    },

    explanation:
      calculatedDMARCPass
        ? `DMARC passes because ${passedBy.toUpperCase()} provides an authenticated identifier aligned with the Header From domain.`
        : "DMARC fails because neither an authenticated aligned SPF identifier nor an authenticated aligned DKIM identifier was available."
  };
}

// ===========================================================
// ROOT
// ===========================================================

app.get("/", (req, res) => {
  res.json({
    success: true,

    message:
      "Email Forensics Verification Server is running",

    verification: {
      spf:
        "Independent SPF DNS verification",

      dkim:
        "Independent DKIM cryptographic signature verification",

      dmarc:
        "Independent DMARC DNS policy and explicit SPF/DKIM alignment verification",

      arc:
        "ARC verification reported separately"
    }
  });
});

// ===========================================================
// VERIFY EML
// ===========================================================

app.post(
  "/verify",
  upload.single("email"),
  async (req, res) => {
    try {

      // -----------------------------------------------------
      // Validate upload
      // -----------------------------------------------------

      if (!req.file) {
        return res.status(400).json({
          success: false,
          message:
            "Please upload a complete .eml file"
        });
      }

      const rawEmail =
        req.file.buffer;

      // -----------------------------------------------------
      // Extract forensic SMTP evidence
      // -----------------------------------------------------

      const envelopeSender =
        extractEnvelopeSender(rawEmail);

      const headerFrom =
        extractHeaderFrom(rawEmail);

      const smtp =
        extractSMTPInfo(rawEmail);

      const dkimHeaders =
        extractDKIMHeaders(rawEmail);

      const envelopeSenderDomain =
        extractEmailDomain(
          envelopeSender
        );

      const headerFromDomain =
        extractEmailDomain(
          headerFrom
        );

      // -----------------------------------------------------
      // Console evidence
      // -----------------------------------------------------

      console.log(
        "\n=============================================="
      );

      console.log(
        "      EMAIL FORENSICS AUTHENTICATION"
      );

      console.log(
        "=============================================="
      );

      console.log(
        "Envelope Sender:",
        envelopeSender
      );

      console.log(
        "Envelope Domain:",
        envelopeSenderDomain
      );

      console.log(
        "Header From:",
        headerFrom
      );

      console.log(
        "Header From Domain:",
        headerFromDomain
      );

      console.log(
        "Client IP:",
        smtp.ip
      );

      console.log(
        "HELO:",
        smtp.helo
      );

      console.log(
        "SMTP Hops:",
        smtp.hops
      );

      console.log(
        "DKIM Headers:",
        dkimHeaders
      );

      console.log(
        "==============================================\n"
      );

      // -----------------------------------------------------
      // Required SMTP information
      // -----------------------------------------------------

      if (
        !envelopeSender ||
        !envelopeSenderDomain ||
        !smtp.ip
      ) {
        return res.status(400).json({
          success: false,

          message:
            "Insufficient SMTP evidence for independent SPF verification.",

          smtpEvidence: {
            envelopeSender,

            envelopeSenderDomain,

            headerFrom,

            headerFromDomain,

            clientIp:
              smtp.ip,

            helo:
              smtp.helo,

            routingHops:
              smtp.hops
          }
        });
      }

      // -----------------------------------------------------
      // INDEPENDENT AUTHENTICATION
      // -----------------------------------------------------

      const authResult =
        await authenticate(
          rawEmail,
          {
            sender:
              envelopeSender,

            ip:
              smtp.ip,

            helo:
              smtp.helo || "",

            trustReceived:
              false
          }
        );

      // -----------------------------------------------------
      // Extract actual authentication results
      // -----------------------------------------------------

      const spfResult =
        authResult?.spf ||
        null;

      const dkimResult =
        authResult?.dkim ||
        null;

      const dmarcResult =
        authResult?.dmarc ||
        null;

      const arcResult =
        authResult?.arc ||
        null;

      // -----------------------------------------------------
      // Normalize DKIM results for alignment
      // -----------------------------------------------------

      let dkimVerificationResults = [];

      if (
        Array.isArray(
          dkimResult?.results
        )
      ) {
        dkimVerificationResults =
          dkimResult.results;

      } else if (
        Array.isArray(
          dkimResult
        )
      ) {
        dkimVerificationResults =
          dkimResult;
      }

      // -----------------------------------------------------
      // EXPLICIT DMARC ALIGNMENT
      // -----------------------------------------------------

      const alignment =
        calculateDMARCAlignment({
          fromDomain:
            headerFromDomain,

          envelopeSenderDomain:
            envelopeSenderDomain,

          dkimResults:
            dkimVerificationResults,

          dmarcResult:
            dmarcResult
        });

      // -----------------------------------------------------
      // Compare mailauth DMARC result with
      // explicit alignment calculation
      // -----------------------------------------------------

      const mailauthDMARCResult =
        dmarcResult?.status?.result ||
        dmarcResult?.result ||
        null;

      const independentDMARCResult =
        alignment?.dmarc?.calculatedResult ||
        null;

      // -----------------------------------------------------
      // Final response
      // -----------------------------------------------------

      const response = {

        success: true,

        fileName:
          req.file.originalname,

        verificationType:
          "Independent email authentication verification",

        smtpEvidence: {

          envelopeSender,

          envelopeSenderDomain,

          headerFrom,

          headerFromDomain,

          clientIp:
            smtp.ip,

          helo:
            smtp.helo,

          routingHops:
            smtp.hops,

          receivedHeaders:
            smtp.allReceived,

          source:
            "Return-Path, From and Received headers from uploaded EML"
        },

        verificationMethod: {

          spf:
            "Independent SPF DNS evaluation using supplied SMTP IP and envelope sender",

          dkim:
            "Independent DKIM cryptographic signature verification using DNS public keys",

          dmarc:
            "Independent DMARC policy evaluation plus explicit SPF/DKIM identifier alignment",

          arc:
            "ARC chain verification reported separately"
        },

        authentication: {

          spf:
            spfResult,

          dkim:
            dkimResult,

          dmarc:
            dmarcResult,

          arc:
            arcResult
        },

        explicitDMARCAlignment: {

          ...alignment,

          mailauthDMARCResult,

          independentDMARCResult,

          resultsAgree:
            mailauthDMARCResult
              ? String(
                  mailauthDMARCResult
                ).toLowerCase() ===
                String(
                  independentDMARCResult
                ).toLowerCase()
              : null
        },

        summary: {

          spf:
            spfResult?.status?.result ||
            spfResult?.result ||
            null,

          dkim:
            dkimResult?.results?.[0]
              ?.status?.result ||
            dkimResult?.status?.result ||
            null,

          dmarc:
            mailauthDMARCResult,

          dmarcAlignment:
            alignment?.dmarc
              ?.calculatedResult ||
            null,

          dmarcPassedBy:
            alignment?.dmarc
              ?.passedBy ||
            "none"
        },

        comparison: {

          independentSPF:
            spfResult?.status?.result ||
            spfResult?.result ||
            null,

          independentDKIM:
            dkimResult?.results?.[0]
              ?.status?.result ||
            dkimResult?.status?.result ||
            null,

          mailauthDMARC:
            mailauthDMARCResult,

          explicitDMARC:
            independentDMARCResult,

          dmarcResultsAgree:
            mailauthDMARCResult
              ? String(
                  mailauthDMARCResult
                ).toLowerCase() ===
                String(
                  independentDMARCResult
                ).toLowerCase()
              : null
        }
      };

      // -----------------------------------------------------
      // Console final result
      // -----------------------------------------------------

      console.log(
        "\n========== FINAL AUTHENTICATION =========="
      );

      console.log(
        "SPF:",
        response.summary.spf
      );

      console.log(
        "DKIM:",
        response.summary.dkim
      );

      console.log(
        "DMARC:",
        response.summary.dmarc
      );

      console.log(
        "SPF Alignment:",
        alignment.spf.dmarcAligned
      );

      console.log(
        "DKIM Alignment:",
        alignment.dkim.aligned
      );

      console.log(
        "DMARC Passed By:",
        alignment.dmarc.passedBy
      );

      console.log(
        "==========================================\n"
      );

      return res.json(response);

    } catch (error) {

      console.error(
        "\nVerification error:"
      );

      console.error(error);

      return res.status(500).json({

        success: false,

        message:
          "Email authentication verification failed",

        error:
          error.message,

        stack:
          process.env.NODE_ENV ===
          "development"
            ? error.stack
            : undefined
      });
    }
  }
);

// ===========================================================
// START SERVER
// ===========================================================

app.listen(
  PORT,
  () => {
    console.log(
      `Verification server running on http://localhost:${PORT}`
    );
  }
);
