# 🛡️ Scam Checker

A pattern-based scam detection engine that analyzes text, emails, and screenshots to identify phishing, impersonation, and social engineering attacks.

---

## 🚀 Features

- 📄 **Paste Text Analysis**
  - Detects phishing, impersonation, threats, and social engineering

- 📧 **Email (.eml) Parsing**
  - Extracts sender, subject, metadata, and content

- 🖼️ **Screenshot / Image Analysis (OCR)**
  - Uses OCR to extract and analyze text from images

- 🔗 **URL & Domain Intelligence**
  - Detects suspicious links and domain patterns
  - Safe-domain softening for trusted providers

- 🧠 **Pattern-Based Scoring Engine**
  - Detects:
    - urgency
    - threats
    - impersonation
    - payment pressure
    - credential harvesting
    - suspicious domains

- 🧪 **Built-in Regression Test Suite**
  - Ensures detection accuracy over time
  - Visual pass/fail indicators in UI

---

## 📊 Example Output

- Risk Level: **High / Medium / Low**
- Risk Score: numeric scoring system
- Scam Type:
  - Phishing
  - Brand impersonation
  - Payment scam
  - Social engineering
- Red Flags detected
- Recommended next steps

---

## 🧰 Tech Stack

- **Backend:** Node.js, Express
- **Frontend:** Vanilla JS (served from `/public`)
- **OCR:** Tesseract.js
- **Email Parsing:** mailparser
- **File Uploads:** multer

---

## 📁 Project Structure
