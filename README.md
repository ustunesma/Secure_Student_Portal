# 🔐 Secure Student Portal

This project is a secure web application developed using Flask for the SWE210 Software Security course.  
It simulates a student portal system where students can view their grades and teachers/admins can manage them securely.

---

## 🚀 Features

- User authentication (login/register)
- Password hashing using bcrypt
- Role-Based Access Control (Admin / Teacher / Student)
- CSRF protection for all forms
- Session timeout & secure cookies
- Login attempt limit (brute-force protection)
- Account lock after failed login attempts
- Password change functionality
- Encrypted storage of grades and notes (Fernet)
- SQL injection protection (parameterized queries)
- Admin and teacher dashboards
- Teacher account creation system

---

## 🛡️ Security Features

- Strong password policy (length, complexity, no spaces)
- Bcrypt password hashing
- CSRF protection with Flask-WTF
- Session security (HttpOnly, SameSite)
- Rate limiting (Flask-Limiter)
- Brute-force login protection
- Role-based authorization
- Data encryption at rest (Fernet)
- Environment variable configuration (.env)

---

## 🧰 Technologies Used

- Python
- Flask
- SQLite
- Flask-WTF
- Flask-Limiter
- bcrypt
- cryptography (Fernet)
- python-dotenv

---

## ▶️ How to Run

```bash
pip install -r requirements.txt
python app.py