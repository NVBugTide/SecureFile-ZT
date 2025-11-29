# SecureFile-ZT
A zero-trust, client-side file encryption web app built with AES-256-GCM and PBKDF2-HMAC-SHA-256 for secure password-derived encryption, with support for generating self-decrypting HTML files.

🌐 Live App: [https://nvbugtide.github.io/SecureFileZero/ ](https://nvbugtide.github.io/SecureFile-ZT/) 

---

## Features

- **100% local cryptography (browser-only) - zero server storage**
- **AES-256-GCM authenticated encryption**
- **PBKDF2-HMAC-SHA-256 key derivation**
- **Drag-and-drop file input**
- **Generates encrypted .sfz containers**
- **Exports self-decrypting HTML files**
- **Offline - PWA-capable**

---

## 🔐 Security Approach

- Encryption and decryption occur entirely using `window.crypto.subtle`
- Password does **not** leave the local device
- Keys are derived using PBKDF2-HMAC-SHA-256
- AES-GCM provides confidentiality + authentication
- Each encryption uses:
  - fresh random salt
  - fresh random IV
Two encryptions of the same file with the same password will produce different ciphertext.

---

## 📦 File Formats Produced

- `.sfz` — encrypted binary container
- `.decrypt.html` — self-contained HTML decryption page
  - includes encrypted payload
  - decrypts offline in any modern browser

---

## 🚀 Running the App Locally

No dependencies, no build tools.  
Just clone and open `index.html`/ Install as a Progressive Web App

```bash
git clone https://github.com/NVBugTide/SecureFileZero
cd SecureFileZero
open index.html
