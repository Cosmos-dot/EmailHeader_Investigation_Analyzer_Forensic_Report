# Phase 3 v2 — Actual Authentication Engine + .EML Upload

This version lets you upload the **original `.eml` email source** directly to the Phase 3 engine.

## Real verification

- SPF: live DNS lookup + SPF evaluation
- DKIM: DKIM-Signature parsing + DNS public-key lookup + canonicalization + body hash + cryptographic signature verification
- DMARC: live DNS policy lookup + SPF/DKIM authentication + alignment evaluation

## 1. Install

Open VS Code Terminal inside `Phase3_Engine_v2_EML_Upload`:

```powershell
npm install
```

## 2. Start

```powershell
npm start
```

Expected:

```text
🚀 Phase 3 v2 running on http://localhost:5001
📧 EML upload endpoint: POST http://localhost:5001/analyze-file
```

## 3. Test health

```powershell
Invoke-RestMethod -Uri "http://localhost:5001/" -Method GET
```

## 4. Upload an EML file from PowerShell

Replace the path with your actual `.eml` file:

```powershell
$form = @{
    email = Get-Item "C:\Users\YourName\Downloads\original-email.eml"
}

Invoke-RestMethod `
    -Uri "http://localhost:5001/analyze-file" `
    -Method POST `
    -Form $form
```

## 5. Upload with SMTP information

For the most accurate SPF verification, provide the actual SMTP client IP,
HELO/EHLO hostname and MAIL FROM address when you know them:

```powershell
$form = @{
    email = Get-Item "C:\Users\YourName\Downloads\original-email.eml"
    clientIp = "203.0.113.10"
    helo = "mail.example.com"
    sender = "sender@example.com"
}

Invoke-RestMethod `
    -Uri "http://localhost:5001/analyze-file" `
    -Method POST `
    -Form $form
```

## 6. React/frontend request

Send the `.eml` file as multipart form data:

```javascript
const formData = new FormData();
formData.append("email", file);

const response = await fetch("http://localhost:5001/analyze-file", {
  method: "POST",
  body: formData
});

const data = await response.json();
console.log(data);
```

Do NOT manually set the `Content-Type` header. The browser sets the multipart boundary automatically.

## Important forensic rule

Use the original `.eml` source whenever possible. Do not edit, reformat, copy/paste,
or remove headers before analysis. DKIM cryptographic verification depends on the
original signed message structure and body.

The tool will report verification status rather than treating an existing
`Authentication-Results` header as independent proof.
