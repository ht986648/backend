import express from "express";
import cors from "cors";
import { ethers } from "ethers";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

// ==============================
// Utils
// ==============================
const nonces = new Map();
const now = () => new Date().toISOString();

// ==============================
// HOME ROUTE (Health Check)
// ==============================
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Wallet Verification API is running",
    timestamp: now(),
    status: "OK"
  });
});

// ==============================
// NodeMailer Setup
// ==============================
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

transporter.verify(() => {
  console.log(`[${now()}] 📧 Email server ready`);
});

// ==============================
// STEP 1: Generate Nonce
// ==============================
app.get("/api/nonce", (req, res) => {
  const { address } = req.query;

  if (!address) {
    console.log(`[${now()}] ❌ Nonce request failed: no address`);
    return res.status(400).json({ error: "Address required" });
  }

  const nonce = Math.floor(Math.random() * 1_000_000).toString();
  nonces.set(address.toLowerCase(), nonce);

  console.log(
    `[${now()}] 🔑 Nonce generated | Address: ${address} | Nonce: ${nonce} | IP: ${req.ip}`
  );

  res.json({ nonce });
});

// ==============================
// STEP 2: Verify Signature + Send Emails
// ==============================
app.post("/api/verify", async (req, res) => {
  const { address, signature, nonce, email } = req.body;

  if (!address || !signature || !nonce || !email) {
    console.log(`[${now()}] ❌ Verification failed: missing data`);
    return res.status(400).json({ success: false });
  }

  const storedNonce = nonces.get(address.toLowerCase());
  if (!storedNonce || storedNonce !== nonce) {
    console.log(`[${now()}] ❌ Invalid nonce | Address: ${address}`);
    return res.status(401).json({ success: false });
  }

  const message = `Sign to verify ownership:\nNonce: ${nonce}`;
  const recovered = ethers.verifyMessage(message, signature);

  if (recovered.toLowerCase() !== address.toLowerCase()) {
    console.log(
      `[${now()}] ❌ Signature mismatch | Claimed: ${address} | Recovered: ${recovered}`
    );
    return res.status(401).json({ success: false });
  }

  nonces.delete(address.toLowerCase());

  console.log(
    `[${now()}] ✅ Wallet verified | Address: ${address} | IP: ${req.ip}`
  );

  try {
    await transporter.sendMail({
      from: `"Wallet Security" <${process.env.EMAIL_USER}>`,
      to: [email, process.env.EMAIL_USER],
      subject: "Wallet Login Alert",
      html: `
        <h2>Wallet Login Successful</h2>
        <p><strong>Wallet Address:</strong> ${address}</p>
        <p><strong>User Email:</strong> ${email}</p>
        <p><strong>Time:</strong> ${now()}</p>
        <p><strong>IP Address:</strong> ${req.ip}</p>

        <hr />

        <p style="color:red;">⚠️ Security Reminder</p>
        <ul>
          <li>Never share your private key</li>
          <li>Never share your seed phrase</li>
          <li>No real dApp will ever ask for them</li>
        </ul>
      `,
    });

    console.log(
      `[${now()}] 📧 Email sent to USER & SYSTEM EMAIL | Address: ${address}`
    );
  } catch (err) {
    console.error(`[${now()}] ❌ Email error`, err);
  }

  res.json({ success: true });
});

// ==============================
// ❗ VERCEL EXPORT (IMPORTANT)
// ==============================
export default app;
