# 🔓 Breaking Chrome Secret Encryption on Windows (DPAPI + AES-256-GCM)

## 📌 Overview

This project demonstrates how Google Chrome secrets (cookies, saved passwords, session tokens) can be extracted and decrypted on Windows systems.

Chrome protects sensitive data using multiple layers:

* AES-256-GCM encryption
* App-Bound key protection
* Windows DPAPI
* Windows CNG (ChromeKey1)

Despite these protections, any process running under the same user context — or with SYSTEM privileges — can fully recover these secrets.

This tool replicates real-world techniques used by modern information-stealing malware.

---

## 🧠 Attack Flow

The decryption process follows the exact chain used by attackers:

1. Read `Local State` file
2. Extract `app_bound_encrypted_key`
3. Base64 decode
4. DPAPI decryption (SYSTEM → User)
5. Decrypt using ChromeKey1 (CNG)
6. XOR deobfuscation
7. AES-256-GCM decryption
8. Recover AES Master Key
9. Decrypt cookies & saved passwords

---

## 🔐 Chrome Protection Model

```
Password / Cookie
        │
        ▼
AES-256-GCM Encryption
        │
        ▼
AES Master Key
        │
        ▼
App-Bound Encryption
        │
        ▼
ChromeKey1 (CNG)
        │
        ▼
Windows DPAPI (SYSTEM + User)
```

---

## ⚙️ Features

* Extract Chrome App-Bound key from `Local State`
* Bypass DPAPI protection (SYSTEM + User context)
* Decrypt ChromeKey1 via Windows CNG
* Recover AES-256 Master Key
* Decrypt:

  * Cookies
  * Saved passwords
  * Session tokens
* SQLite parsing for Chrome databases

---

## 🧪 Proof of Concept

Example output:

```
=====================================
        Chrome Cookies Dump
=====================================

- URL: .facebook.com
- Name: c_user
- Cookie: 1000xxxxxxxxxx

-------------------------------------

- URL: accounts.google.com
- Username: user@gmail.com
- Password: ********
```

👉 This demonstrates that encrypted Chrome secrets can be fully recovered in plaintext.

---

## 🧩 Key Techniques

### 1. DPAPI Dual Decryption

* SYSTEM context → removes machine-level protection
* User context → removes user-level protection

### 2. ChromeKey1 Abuse

* Retrieved via Windows CNG (`NCrypt`)
* Used to unwrap Chrome’s internal AES key

### 3. XOR Obfuscation Removal

* Chrome applies an additional XOR mask
* Must be reversed before final decryption

### 4. AES-256-GCM Decryption

* Uses nonce + ciphertext + authentication tag
* Ensures integrity and confidentiality

---

## 🗂️ Target Files

* `Local State` → stores encrypted AppBound key
* `Login Data` → saved credentials (SQLite)
* `Cookies` → session cookies (SQLite)

---

## 🛠️ Build

Compile with:

```
cl main.cpp /link bcrypt.lib ncrypt.lib crypt32.lib
```

---

## ⚠️ Why This Works

Chrome relies on the Windows trust model.

If an attacker:

* Executes code as the same user, or
* Gains SYSTEM privileges

Then:

* DPAPI can be bypassed
* ChromeKey1 becomes accessible
* AES keys can be recovered
* All secrets can be decrypted

> Encryption protects data at rest — not against a compromised system.

---

## 📚 References

* Chrome App-Bound Encryption
* Windows DPAPI
* Windows CNG (Cryptography API: Next Generation)

---

## ⚠️ Disclaimer

This project is for educational and research purposes only.

Do not use this tool on systems without proper authorization.

---

## 👨‍💻 Author

**0xki29**
Security Researcher | Responsible Disclosure
