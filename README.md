# Secure Login System with User Role Management

A secure Flask web application implementing authentication, authorization, and role-based access control (RBAC) for **Admin** and **User** roles.

## Project Objective
This project demonstrates practical cybersecurity concepts in software development:
- secure user registration and login
- password hashing using `bcrypt`
- role-based access control
- CAPTCHA-based brute-force friction
- account lockout after repeated failed login attempts
- input validation and SQL Injection resistance via ORM

## Tech Stack
- Python 3.10+
- Flask
- Flask-SQLAlchemy (SQLite by default)
- Flask-Login (session-based authentication)
- Flask-WTF (CSRF protection)
- bcrypt
- pytest

## Features Implemented
- Public pre-login home page with profile intro
- Public registration with fields: username, email, password (always `user` role)
- Client + server-side validation
- Password hashing with `bcrypt`
- Login with email/password + CAPTCHA
- Session cookie authentication
- Admin/User dashboards
- Members page for logged-in users (view admins + users)
- Admin-only user management:
  - separate **Add Member** page
  - separate **Moderation** page
  - add new member (`user` or `admin`)
  - temporary block account for custom minutes
  - disable/enable account
  - delete account
  - change user role
  - unlock locked accounts
- light/dark theme toggle
- Secure hall-of-fame and bounty-post upload module (admin only)
- Auto-arranged hall-of-fame/bounty cards on home page
- Account lockout after multiple failed login attempts
- Error pages (403/404/500)
- Automated tests for core auth/security behavior

## Security Controls
- Password hashing: `bcrypt`
- CSRF protection on POST forms
- Session hardening flags (`HttpOnly`, `SameSite`)
- Input validation for username/email/password/role
- Upload validation for file type, MIME type, and file size
- Safe file naming with generated server-side names
- Files served by database ID (path traversal/LFI-safe)
- SQL Injection mitigation through SQLAlchemy ORM
- CAPTCHA challenge on login
- Security headers (`CSP`, `X-Frame-Options`, `nosniff`, `Referrer-Policy`)
- Account lockout policy:
  - configurable failed-attempt threshold
  - configurable lockout duration

## Setup Instructions
1. Clone repository and enter it:
```bash
git clone <your-repo-url>
cd secure-auth-system
```

2. Create virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. (Optional) configure environment variables:
```bash
cp .env.example .env
```

5. Run application:
```bash
python run.py
```

6. Open browser:
- `http://127.0.0.1:5000`

## Default Behavior
- Database file: `instance/secure_auth.db` (auto-created)
- Tables auto-created on app startup
- No default hardcoded credentials

## Running Tests
```bash
pytest -q
```

## Suggested Screenshot Checklist
Add screenshots to `docs/screenshots/` and reference them below:
- `01-register.png` (registration page)
- `02-login.png` (login with CAPTCHA)
- `03-user-dashboard.png` (user view)
- `04-admin-dashboard.png` (admin user management)
- `05-lockout-message.png` (lockout after failed attempts)

## Submission Notes (Internship)
Before submission, include:
- GitHub repository link
- Updated screenshots in `docs/screenshots/`
- `REPORT.md` summary
- Proof PDFs sent to: `vaulttecconsultancy@gmail.com`
- Deadline: **February 28, 2026**
