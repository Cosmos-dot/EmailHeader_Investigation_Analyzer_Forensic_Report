const fs = require("fs");

const file = process.argv[2];
if (!file) {
  console.error("Usage: node test-eml.js path\\to\\email.eml");
  process.exit(1);
}

const boundary = "----Phase3EMLBoundary";
const data = fs.readFileSync(file);

const head =
  `--${boundary}\r\n` +
  `Content-Disposition: form-data; name="email"; filename="${file.split(/[\\/]/).pop()}"\r\n` +
  `Content-Type: message/rfc822\r\n\r\n`;

const tail = `\r\n--${boundary}--\r\n`;
const body = Buffer.concat([Buffer.from(head), data, Buffer.from(tail)]);

fetch("http://localhost:5001/analyze-file", {
  method: "POST",
  headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
  body
})
.then(async r => {
  const text = await r.text();
  console.log(text);
  if (!r.ok) process.exit(1);
})
.catch(err => {
  console.error(err);
  process.exit(1);
});
