function unfoldHeaderLines(header) {
  return String(header || "")
    .replace(/\r\n[ \t]+/g, " ")
    .replace(/\n[ \t]+/g, " ");
}

function parseHeader(header) {
  const unfolded = unfoldHeaderLines(header);
  const lines = unfolded.split(/\r?\n/);
  const fields = [];

  for (const line of lines) {
    if (!line.trim()) continue;

    const index = line.indexOf(":");
    if (index === -1) continue;

    fields.push({
      name: line.slice(0, index).trim(),
      value: line.slice(index + 1).trim()
    });
  }

  const byName = {};
  for (const field of fields) {
    const key = field.name.toLowerCase();
    if (!byName[key]) byName[key] = [];
    byName[key].push(field.value);
  }

  return { fields, byName, fieldCount: fields.length };
}

function splitRawEmail(rawEmail) {
  const normalized = String(rawEmail || "").replace(/\r\n/g, "\n");
  const separator = normalized.indexOf("\n\n");

  if (separator === -1) {
    return { header: normalized, body: "" };
  }

  return {
    header: normalized.slice(0, separator),
    body: normalized.slice(separator + 2)
  };
}

module.exports = { parseHeader, splitRawEmail };
