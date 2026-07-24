const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 3001);
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY;
const ROCKETCHAT_WEBHOOK_URL = process.env.ROCKETCHAT_WEBHOOK_URL;

/**
 * Checks the API key supplied by the caller.
 */
function requireApiKey(req, res, next) {
  const providedKey = req.get("x-api-key");

  if (!BRIDGE_API_KEY) {
    return res.status(500).json({
      success: false,
      error: "BRIDGE_API_KEY is not configured"
    });
  }

  if (!providedKey || providedKey !== BRIDGE_API_KEY) {
    return res.status(403).json({
      success: false,
      error: "Forbidden"
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "NodeSend",
    endpoints: {
      health: "GET /health",
      email: "POST /send",
      rocketchat: "POST /rocketchat"
    }
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "NodeSend",
    status: "healthy",
    rocketchatConfigured: Boolean(ROCKETCHAT_WEBHOOK_URL)
  });
});

/**
 * Send an email using SMTP settings supplied in the request.
 */
app.post("/send", requireApiKey, async (req, res) => {
  try {
    const { config, email } = req.body || {};

    if (!config || !email) {
      return res.status(400).json({
        success: false,
        error: "Both config and email are required"
      });
    }

    const host = String(config.host || "").trim();
    const port = Number(config.port);
    const username = String(config.username || "").trim();
    const password = String(config.password || "");

    const from = String(email.from || "").trim();
    const to = email.to;
    const subject = String(email.subject || "");
    const text = email.text;
    const html = email.html;
    const cc = email.cc;
    const bcc = email.bcc;

    if (!host || !port || !username || !password) {
      return res.status(400).json({
        success: false,
        error: "SMTP host, port, username and password are required"
      });
    }

    if (!from || !to || !subject) {
      return res.status(400).json({
        success: false,
        error: "Email from, to and subject are required"
      });
    }

    if (!text && !html) {
      return res.status(400).json({
        success: false,
        error: "Email text or html content is required"
      });
    }

    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: {
        user: username,
        pass: password
      }
    });

    await transporter.verify();

    const result = await transporter.sendMail({
      from,
      to,
      cc,
      bcc,
      subject,
      text,
      html
    });

    res.json({
      success: true,
      messageId: result.messageId,
      accepted: result.accepted,
      rejected: result.rejected
    });
  } catch (error) {
    console.error("Email error:", error);

    res.status(500).json({
      success: false,
      error: error.message || "Email could not be sent"
    });
  }
});

/**
 * Send a message through a Rocket.Chat incoming webhook.
 */
app.post("/rocketchat", requireApiKey, async (req, res) => {
  try {
    if (!ROCKETCHAT_WEBHOOK_URL) {
      return res.status(500).json({
        success: false,
        error: "ROCKETCHAT_WEBHOOK_URL is not configured"
      });
    }

    const {
      text,
      channel,
      username,
      emoji,
      avatar,
      alias,
      attachments
    } = req.body || {};

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "text is required"
      });
    }

    const payload = {
      text
    };

    if (channel) payload.channel = channel;
    if (username) payload.username = username;
    if (alias) payload.alias = alias;
    if (emoji) payload.emoji = emoji;
    if (avatar) payload.avatar = avatar;
    if (attachments) payload.attachments = attachments;

    const response = await fetch(ROCKETCHAT_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const responseText = await response.text();

    let responseBody;

    try {
      responseBody = JSON.parse(responseText);
    } catch {
      responseBody = responseText;
    }

    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: "Rocket.Chat rejected the request",
        details: responseBody
      });
    }

    res.json({
      success: true,
      rocketchat: responseBody
    });
  } catch (error) {
    console.error("Rocket.Chat error:", error);

    res.status(500).json({
      success: false,
      error: error.message || "Rocket.Chat message could not be sent"
    });
  }
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`NodeSend listening on 0.0.0.0:${PORT}`);
});
