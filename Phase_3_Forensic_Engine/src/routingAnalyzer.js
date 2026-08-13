function analyzeRouting(parsed) {
  const received = parsed.byName["received"] || [];

  const hops = received.map((value, index) => {
    const from = value.match(/\bfrom\s+([^\s(]+)/i);
    const by = value.match(/\bby\s+([^\s;]+)/i);
    const bracketIp = value.match(/\[([0-9A-Fa-f:.]+)\]/);

    return {
      hop: index + 1,
      from: from ? from[1] : null,
      by: by ? by[1] : null,
      ip: bracketIp ? bracketIp[1] : null,
      raw: value
    };
  });

  return {
    hopCount: hops.length,
    hops,
    oldestToNewest: [...hops].reverse()
  };
}

module.exports = { analyzeRouting };
