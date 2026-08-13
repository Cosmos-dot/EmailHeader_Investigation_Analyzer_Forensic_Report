function classifyThreat(score) {
  if (score >= 70) {
    return {
      classification: "HIGH RISK",
      description: "Multiple authentication or header indicators are consistent with spoofing or malicious email activity."
    };
  }

  if (score >= 40) {
    return {
      classification: "MEDIUM RISK",
      description: "The message has authentication or header anomalies that require review."
    };
  }

  return {
    classification: "LOW RISK",
    description: "No major authentication anomaly was identified by the configured checks."
  };
}

module.exports = { classifyThreat };
