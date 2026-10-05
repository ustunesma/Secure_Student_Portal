# 🛡️ SecurePortal — Secure Student Grade Portal

**Team:** [Esma Üstün], [Tuana Ülbeği], [Batuhan Şahin]

A role-based web application built with Flask for the SWE210 Software Security group project.
Includes features such as authentication, role-based access control (RBAC), and encrypted data storage.

---
## 📖 Project Overview

This project was developed as a group project for the SWE210 Software Security course using Flask.

The system is designed as a simple student portal where students can view their grades, teachers can manage grades, and admins can manage the overall system.

The main purpose of the project was to apply software security concepts in a practical web application. During development, we focused on improving both usability and security.

The project includes security features such as password hashing with bcrypt, role-based access control, CSRF protection, encrypted grade storage using Fernet, session timeout, brute-force protection, and secure session management.

Through this project, we gained practical experience in Flask development and learned how security mechanisms can be applied in a real application.

## 📁 Project Structure

```
SECURE_PORTAL/
├── app.py                   # Main Flask application
├── requirements.txt         # Python dependencies
├── .env                     # Environment secrets (never commit this)
├── .gitignore
├── README.md
├── LICENSE
├── static/
│   └── js/
│       └── strength.js      # Real-time password strength meter
└── templates/
    ├── base.html            # Shared navbar + layout
    ├── login.html
    ├── register.html
    ├── dashboard.html       # Student read-only grade view
    ├── teacher.html         # Teacher grade management panel
    ├── admin.html           # Full admin panel
    ├── change_password.html
    ├── logs.html            # Security audit dashboard
    └── 429.html             # Rate limit error page
```

---

## ⚙️ Setup & Installation

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Create your `.env` file

Create a file named `.env` in the project root:

```env
ADMIN_PASSWORD=YourStrongPassword123!
SECRET_KEY=replace-with-your-own-secret-key
FERNET_KEY=replace-with-your-own-fernet-key
```

> ⚠️ `ADMIN_PASSWORD` must be at least 8 characters and contain uppercase, lowercase, a digit, and a special character.

### 3. Run the app

```bash
python app.py
```

Then open: **http://127.0.0.1:5000**

> The database (`portal.db`) and encryption key (`secret.key`) are auto-created on first run.

---

## 👥 User Roles

| Role | Panel | Can Do |
|---|---|---|
| **Admin** | `/admin` | Create/delete teachers, manage students, assign/edit/delete all grades, unlock accounts, view security logs |
| **Teacher** | `/teacher` | Assign grades to students, edit/delete their own grades only |
| **Student** | `/dashboard` | View their own assigned grades (read-only) |

---

## 🔐 Security Features

### Authentication
- **bcrypt** password hashing with automatic salt — passwords never stored in plaintext
- Strong password policy: 8+ chars, uppercase, lowercase, digit, special character
- Brute-force lockout: account locked for 60 seconds after 3 failed attempts (tracked in database, not session)
- Real-time password strength meter on registration page

### Access Control (RBAC)
- Three-role system enforced via Python decorator functions (`@login_required`, `@admin_required`, `@teacher_required`)
- Teachers can only see and modify grades **they personally assigned** (`assigned_by` column)
- 30-minute session inactivity timeout
- IP-based rate limiting: 5 login attempts/min, 3 registration attempts/min
- Custom 429 page with countdown timer on rate limit

### Encryption
- **Fernet** symmetric encryption on grade and notes data
- Sensitive grade and notes data are encrypted before being stored in the database
- Encryption key loaded from environment variable (`FERNET_KEY`) or `secret.key` file

### Additional
- **CSRF protection** on every HTML form (Flask-WTF)
- **Security audit logging** — all login attempts, account actions, and admin operations written to `security_audit.log`
- **Security Audit Dashboard** at `/admin/logs` (admin only, last 50 events)
- Session cookies: `HttpOnly=True`, `SameSite=Lax`, `Secure=True` in production
- `debug=False` automatically set when `FLASK_ENV=production`

---

## 📦 Dependencies

```
Flask
Flask-WTF
Flask-Limiter
bcrypt
cryptography
python-dotenv
```

---

## 🗄️ Database Tables

**users**
| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| username | TEXT | Unique username |
| password | TEXT | bcrypt hash |
| role | TEXT | 'admin' / 'teacher' / 'user' |
| login_attempts | INTEGER | Failed attempt counter |
| locked_until | REAL | Unix timestamp of lockout expiry |

**grades**
| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary key |
| user_id | INTEGER | Student who owns this grade |
| assigned_by | INTEGER | Teacher/admin who created it |
| course | TEXT | Course name (plaintext) |
| grade_enc | TEXT | Fernet-encrypted grade |
| notes_enc | TEXT | Fernet-encrypted notes |
| date | TEXT | Assignment date |

---

## ⚠️ Important Notes

- **Never delete `secret.key`** while the database has grades — you won't be able to decrypt them.
- **Delete `portal.db`** if you change the database schema (adding columns etc.) and restart fresh.
- The `.env` file is listed in `.gitignore` — never commit it to version control.
- The `security_audit.log` is also in `.gitignore` to protect sensitive event data.

---

## 📄 License

MIT License — see `LICENSE` file for details.

---

*SWE210 Software Security Group Project*