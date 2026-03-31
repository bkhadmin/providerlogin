# Provider Login System 🏥

ระบบ Login ด้วย **Provider ID + Health ID OAuth** อย่างปลอดภัยสูง พร้อม architecture ต่อยอดสำหรับหลาย web applications

## 🚀 การติดตั้งและ Run

### 1. ติดตั้ง Dependencies

```bash
cd e:\workspace\providerlogin
npm install
```

### 2. ตั้งค่า Environment

```bash
# Copy ไฟล์ตัวอย่าง
copy .env.example .env
```

แก้ไขค่าต่อไปนี้ใน `.env`:

| ตัวแปร | คำอธิบาย |
|---|---|
| `PROVIDER_CLIENT_ID` | Client ID จากระบบ Provider ID (สธ.) |
| `PROVIDER_SECRET_KEY` | Secret Key จากระบบ Provider ID (สธ.) |
| `HEALTH_ID_CLIENT_ID` | Client ID ของ Health ID OAuth |
| `HEALTH_ID_CLIENT_SECRET` | Secret ของ Health ID OAuth |
| `JWT_SECRET` | Random string ยาวๆ สำหรับ sign JWT (เปลี่ยนทุกครั้ง!) |

### 3. Start Server

```bash
npm start
# หรือ development mode (hot-reload)
npm run dev
```

เปิด browser ไปที่: **http://localhost:3000**

---

## 🔒 Security Features

| Layer | Implementation |
|---|---|
| **Transport** | HSTS header (force HTTPS) |
| **XSS** | CSP headers + `httpOnly` cookies |
| **CSRF** | Double-Submit Cookie + state nonce |
| **Brute Force** | Rate limit 5 req/15min บน auth endpoints |
| **Clickjacking** | `X-Frame-Options: DENY` |
| **Token Storage** | JWT ใน `httpOnly`, `Secure`, `SameSite=Strict` cookies |
| **Secrets** | ใน `.env` เท่านั้น ไม่ hardcode |
| **Audit Log** | บันทึกทุก auth event → `logs/audit.log` |
| **Pollution** | HPP middleware |

---

## 📁 Project Structure

```
providerlogin/
├── server.js              ← Entry point
├── config/config.js       ← Configuration + validation
├── middleware/
│   ├── security.js        ← Helmet, CORS, Rate limit, CSRF
│   ├── auth.js            ← JWT cookie verifier
│   └── audit.js           ← Winston audit logger
├── controllers/
│   └── auth.controller.js ← OAuth flow logic
├── routes/
│   ├── auth.routes.js     ← /api/auth/*
│   └── apps.routes.js     ← /api/apps/* (ต่อยอด apps)
├── utils/
│   ├── providerApi.js     ← Provider ID API client
│   ├── jwt.js             ← JWT sign/verify
│   └── crypto.js          ← PKCE + state nonce
└── public/                ← Frontend
    ├── index.html         ← Login page
    ├── callback.html      ← OAuth callback
    ├── dashboard.html     ← Post-login dashboard
    └── assets/
        ├── style.css      ← Dark glassmorphism theme
        └── app.js         ← Secure fetch utilities
```

---

## 🔌 เพิ่ม Web Application ใหม่

แก้ไข `routes/apps.routes.js` ในส่วน `allApps` array:

```js
{
  id: 'app-new',
  name: 'ชื่อระบบใหม่',
  description: 'คำอธิบาย',
  icon: '🆕',
  url: 'https://new-app.example.com',
  requiredExpertise: null, // null = ทุกคนเข้าได้ หรือระบุวิชาชีพ
}
```

ระบบจะออก **SSO token** (อายุ 15 นาที) ให้ app ใหม่โดยอัตโนมัติ

---

## 📋 API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/auth/login` | ❌ | เริ่ม OAuth flow |
| GET | `/api/auth/callback` | ❌ | รับ token จาก Health ID |
| GET | `/api/auth/status` | ❌ | ตรวจสอบ login status |
| GET | `/api/auth/profile` | ✅ | ดึงข้อมูล user |
| POST | `/api/auth/logout` | ✅ + CSRF | ออกจากระบบ |
| GET | `/api/apps` | ✅ | รายการ apps ที่มีสิทธิ์ |
| GET | `/api/apps/:id/token` | ✅ | SSO token สำหรับ app |
