function calculateRiskScore(authentication, findings) {
  let score = 0;

  const spf = authentication.spf?.result;
  const dkim = authentication.dkim?.result;
  const dmarc = authentication.dmarc?.result;

  if (spf === "fail" || spf === "permerror") score += 30;
  else if (spf === "softfail") score += 20;
  else if (!spf || spf === "none") score += 10;

  if (dkim === "fail" || dkim === "permerror") score += 30;
  else if (dkim === "neutral" || dkim === "policy") score += 15;
  else if (!dkim || dkim === "none") score += 10;

  if (dmarc === "fail" || dmarc === "permerror") score += 30;
  else if (dmarc === "temperror") score += 15;
  else if (!dmarc || dmarc === "none") score += 5;

  for (const f of findings) {
    if (f.code === "MISSING_FROM") score += 10;
    if (f.code === "FROM_RETURN_PATH_MISMATCH") score += 10;
    if (f.code === "NO_RECEIVED_HEADERS") score += 5;
  }

  return Math.min(100, score);
}

module.exports = { calculateRiskScore };
