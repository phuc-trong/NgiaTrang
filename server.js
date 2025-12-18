require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const OTP_EXPIRES_MS = 5 * 60 * 1000; // 5 minutes

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const otpStore = new Map();
const verifiedEmails = new Set();

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const sanitizeEmail = (email) => (email || '').trim().toLowerCase();
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

app.post('/api/send-otp', async (req, res) => {
  const email = sanitizeEmail(req.body?.email);
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const otp = generateOtp();
  const expiresAt = Date.now() + OTP_EXPIRES_MS;
  otpStore.set(email, { otp, expiresAt });

  const mailOptions = {
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Mã OTP khôi phục mật khẩu',
    text: `Mã OTP của bạn là ${otp}. Mã sẽ hết hạn sau 5 phút.`,
    html: `<p>Mã OTP của bạn là <strong>${otp}</strong>.</p><p>Mã sẽ hết hạn sau 5 phút.</p>`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: 'Đã gửi OTP qua email' });
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ error: 'Không gửi được email. Kiểm tra SMTP cấu hình.' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const email = sanitizeEmail(req.body?.email);
  const otp = (req.body?.otp || '').trim();
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email và OTP là bắt buộc' });
  }

  const entry = otpStore.get(email);
  if (!entry) {
    return res.status(400).json({ error: 'Chưa gửi OTP cho email này' });
  }

  if (Date.now() > entry.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'OTP đã hết hạn' });
  }

  if (otp !== entry.otp) {
    return res.status(400).json({ error: 'OTP không đúng' });
  }

  otpStore.delete(email);
  verifiedEmails.add(email);
  return res.json({ message: 'Xác nhận OTP thành công' });
});

app.post('/api/reset-password', (req, res) => {
  const email = sanitizeEmail(req.body?.email);
  const newPassword = (req.body?.newPassword || '').trim();

  if (!email || !newPassword) {
    return res.status(400).json({ error: 'Email và mật khẩu mới là bắt buộc' });
  }

  if (!verifiedEmails.has(email)) {
    return res.status(400).json({ error: 'Chưa xác thực OTP cho email này' });
  }

  const hasUpper = /[A-Z]/.test(newPassword);
  const hasDigit = /\d/.test(newPassword);

  if (newPassword.length < 8 || !hasUpper || !hasDigit) {
    return res.status(400).json({ error: 'Mật khẩu mới phải >= 8 ký tự, có ít nhất 1 chữ hoa và 1 chữ số' });
  }

  // Demo: ở đây cần lưu mật khẩu mới vào DB (đã hash).
  // Tạm thời chỉ log và trả về thành công.
  console.log(`Password reset for ${email}`);
  verifiedEmails.delete(email);
  return res.json({ message: 'Đặt lại mật khẩu thành công (demo)' });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
