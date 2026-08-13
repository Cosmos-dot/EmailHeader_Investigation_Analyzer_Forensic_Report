const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const { generateForensicReport } = require("./src/forensicReport");

const app = express();
const PORT = process.env.PORT || 5001;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = file.originalname.toLowerCase().endsWith(".eml") ||
                    file.mimetype === "message/rfc822" ||
                    file.mimetype === "application/octet-stream" ||
                    file.mimetype === "text/plain";
    cb(null, allowed);
  }
});

app.use(cors());
app.use(express.json({ limit: "5mb" }));

app.get("/", (req, res) => {
  res.json({
    phase: "Phase 3 v2",
    module: "Actual Email Authentication Engine",
    status: "running",
    upload: ".eml supported",
    verification: {
      spf: "real",
      dkim: "real",
      dmarc: "real"
    }
  });
});

app.post("/analyze", async (req, res) => {
  try {
    const { rawEmail, header, body, clientIp, helo, sender } = req.body || {};

    if (!rawEmail && !header) {
      return res.status(400).json({
        success: false,
        error: "Provide rawEmail or header."
      });
    }

    const report = await generateForensicReport({
      rawEmail,
      header,
      body,
      clientIp,
      helo,
      sender
    });

    res.json({ success: true, report });
  } catch (error) {
    console.error("Analysis error:", error);
    res.status(500).json({
      success: false,
      error: "Authentication analysis failed.",
      details: error.message
    });
  }
});

app.post("/analyze-file", upload.single("email"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "Upload a .eml file using the field name 'email'."
      });
    }

    const rawEmail = req.file.buffer.toString("utf8");

    if (!rawEmail.trim()) {
      return res.status(400).json({
        success: false,
        error: "The uploaded .eml file is empty."
      });
    }

    const report = await generateForensicReport({
      rawEmail,
      clientIp: req.body.clientIp || undefined,
      helo: req.body.helo || undefined,
      sender: req.body.sender || undefined
    });

    res.json({
      success: true,
      filename: req.file.originalname,
      sizeBytes: req.file.size,
      report
    });
  } catch (error) {
    console.error("EML analysis error:", error);
    res.status(500).json({
      success: false,
      error: "Unable to analyze the uploaded .eml file.",
      details: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Phase 3 v2 running on http://localhost:${PORT}`);
  console.log(`📧 EML upload endpoint: POST http://localhost:${PORT}/analyze-file`);
});
