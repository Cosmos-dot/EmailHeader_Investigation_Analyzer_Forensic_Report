const dns = require("dns");
const { authenticate } = require("mailauth");

function resultOf(obj) {
  if (!obj) return null;

  return (
    obj.status?.result ||
    obj.result ||
    obj.status ||
    null
  );
}

function simplifyDkim(dkim) {
  if (!dkim) return null;

  const results = Array.isArray(dkim.results)
    ? dkim.results.map((item) => ({
        result:
          item.result ||
          item.status?.result ||
          item.status ||
          null,

        info: item.info || null,

        domain:
          item.domain ||
          item.signingDomain ||
          item.header?.d ||
          null,

        selector:
          item.selector ||
          item.header?.s ||
          null,

        algorithm:
          item.algorithm ||
          item.algo ||
          item.header?.a ||
          null,

        bodyHashVerified:
          item.bodyHash && item.bodyHashExpecting
            ? item.bodyHash === item.bodyHashExpecting
            : null,

        signatureTimeValid:
          typeof item.signatureTimeValid === "boolean"
            ? item.signatureTimeValid
            : null,

        signTime:
          item.signTime || null,

        expiresAfter:
          item.expiresAfter || null,

        publicKeyFound:
          Boolean(item.publicKey)
      }))
    : [];

  const passCount = results.filter(
    (item) => item.result === "pass"
  ).length;

  const failCount = results.filter(
    (item) =>
      ["fail", "permerror", "temperror"].includes(
        item.result
      )
  ).length;

  let aggregateResult = null;

  if (passCount > 0) {
    aggregateResult = "pass";
  } else if (failCount > 0) {
    aggregateResult =
      results.find((item) =>
        ["fail", "permerror", "temperror"].includes(
          item.result
        )
      )?.result || null;
  } else {
    aggregateResult =
      results[0]?.result ||
      dkim.status?.result ||
      null;
  }

  return {
    result: aggregateResult,

    signatureCount: results.length,

    cryptographicPass:
      passCount > 0,

    results,

    raw: dkim
  };
}

function simplifySpf(spf) {
  if (!spf) return null;

  return {
    result: resultOf(spf),

    domain:
      spf.domain ||
      spf.envelopeFrom ||
      spf.mailFrom ||
      spf.smtp?.mailfrom ||
      null,

    ip:
      spf.ip ||
      spf["client-ip"] ||
      spf.smtp?.clientIp ||
      null,

    clientIp:
      spf["client-ip"] ||
      spf.smtp?.clientIp ||
      null,

    mailFrom:
      spf["envelope-from"] ||
      spf.smtp?.mailfrom ||
      spf.domain ||
      null,

    helo:
      spf.helo ||
      spf.smtp?.helo ||
      null,

    header:
      spf.header || null,

    raw:
      spf
  };
}

function simplifyDmarc(dmarc) {
  if (!dmarc) return null;

  return {
    result: resultOf(dmarc),

    fromDomain:
      dmarc.fromDomain ||
      dmarc.domain ||
      null,

    policy:
      dmarc.policy ||
      dmarc.p ||
      null,

    aligned:
      dmarc.aligned ??
      null,

    header:
      dmarc.header ||
      null,

    raw:
      dmarc
  };
}

async function performAuthentication(message, options) {
  const authOptions = {
    resolver: async (name, rr) => {
      return dns.promises.resolve(name, rr);
    },

    trustReceived:
      options.trustReceived ?? false,

    maxResolveCount: 10,

    maxVoidCount: 2,

    minBitLength: 1024
  };

  if (options.clientIp) {
    authOptions.ip = options.clientIp;
  }

  if (options.helo) {
    authOptions.helo = options.helo;
  }

  if (options.sender) {
    authOptions.sender = options.sender;
  }

  /*
   If SMTP information was not supplied, allow the
   authentication engine to derive the relevant IP
   information from the trusted Received chain.
  */

  if (
    !options.clientIp &&
    !options.helo &&
    !options.sender
  ) {
    authOptions.trustReceived = true;
  }

  const result = await authenticate(
    message,
    authOptions
  );

  return {
    verifiedBy: "mailauth",

    spf: simplifySpf(
      result.spf
    ),

    dkim: simplifyDkim(
      result.dkim
    ),

    dmarc: simplifyDmarc(
      result.dmarc
    ),

    arc:
      result.arc ||
      null,

    receivedChain:
      result.receivedChain ||
      [],

    authenticationHeaders:
      result.headers ||
      null
  };
}

module.exports = {
  performAuthentication
};