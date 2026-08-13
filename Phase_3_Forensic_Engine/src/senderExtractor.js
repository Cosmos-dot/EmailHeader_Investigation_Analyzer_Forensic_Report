function extractEmail(value) {
  if (!value) return null;
  const match = String(value).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0].toLowerCase() : null;
}

function domainFromEmail(email) {
  if (!email || !email.includes("@")) return null;
  return email.split("@").pop().toLowerCase();
}

function extractSender(parsed) {
  const fromRaw = parsed.byName["from"]?.[0] || null;
  const returnPathRaw = parsed.byName["return-path"]?.[0] || null;
  const replyToRaw = parsed.byName["reply-to"]?.[0] || null;

  const from = extractEmail(fromRaw);
  const returnPath = extractEmail(returnPathRaw);
  const replyTo = extractEmail(replyToRaw);

  return {
    from,
    fromDomain: domainFromEmail(from),
    returnPath,
    returnPathDomain: domainFromEmail(returnPath),
    replyTo,
    replyToDomain: domainFromEmail(replyTo)
  };
}

module.exports = { extractEmail, domainFromEmail, extractSender };
