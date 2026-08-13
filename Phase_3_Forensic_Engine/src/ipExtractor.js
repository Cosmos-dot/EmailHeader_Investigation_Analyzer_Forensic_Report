const net = require("net");

function isValidIPv4(ip) {
  return net.isIP(ip) === 4;
}

function isPrivateIPv4(ip) {
  if (!isValidIPv4(ip)) return false;

  const [a, b] = ip.split(".").map(Number);

  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

function extractIPv4(header) {
  const text = String(header || "");
  const candidates = [];
  let match;

  // First check IP addresses inside [ ] in Received headers.
  const bracketRegex = /\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]/g;

  while ((match = bracketRegex.exec(text)) !== null) {
    if (isValidIPv4(match[1])) {
      candidates.push(match[1]);
    }
  }

  // Find normal IPv4 addresses.
  const ipv4Regex =
    /(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/g;

  while ((match = ipv4Regex.exec(text)) !== null) {
    const ip = match[1];
    const octets = ip.split(".");

    // Prevent timestamp fragments such as 07.23.23.41
    // and 23.42.00-like values from being treated as IPs.
    if (
      isValidIPv4(ip) &&
      octets.every(
        octet => !(octet.length > 1 && octet.startsWith("0"))
      )
    ) {
      candidates.push(ip);
    }
  }

  return [...new Set(candidates)];
}

function extractIPv6(header) {
  const text = String(header || "");
  const candidates = [];
  let match;

  // IPv6 addresses inside brackets.
  const bracketRegex = /\[([0-9A-Fa-f:.]+)\]/g;

  while ((match = bracketRegex.exec(text)) !== null) {
    if (net.isIP(match[1]) === 6) {
      candidates.push(match[1]);
    }
  }

  // Other IPv6 literals.
  const ipv6Regex =
    /(?<![A-Za-z0-9])([0-9A-Fa-f:]{2,})(?![A-Za-z0-9])/g;

  while ((match = ipv6Regex.exec(text)) !== null) {
    if (net.isIP(match[1]) === 6) {
      candidates.push(match[1]);
    }
  }

  return [...new Set(candidates)];
}

function extractIPs(header) {
  const ipv4 = extractIPv4(header);
  const ipv6 = extractIPv6(header);

  return {
    ipv4,
    ipv6,
    all: [...new Set([...ipv4, ...ipv6])],
    privateIPv4: ipv4.filter(isPrivateIPv4),
    publicIPv4: ipv4.filter(
      ip => !isPrivateIPv4(ip)
    )
  };
}

module.exports = {
  extractIPs,
  isPrivateIPv4
};