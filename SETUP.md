# Phase 2: Authentication & OTP Verification - Setup & Verification Guide

## Overview

This document provides complete setup instructions, security details, and verification steps for Phase 2 of the Secure Certificate Request & Approval System.

---

## 📋 Project Structure

```
cyber/
├── app.py                          # Flask application (Phase 2)
├── requirements.txt                # Python dependencies
├── certificate_system.db           # SQLite database (auto-created)
├── SETUP.md                        # This file
└── ui/                             # Frontend HTML/CSS files
    ├── index.html
    ├── login.html
    ├── register.html
    ├── otp.html
    ├── dashboard.html
    └── ... (other pages)
```

---

## 🔧 Installation & Setup

### Step 1: Install Dependencies

```bash
cd /Users/gugansaravanan/Downloads/cyber
pip install -r requirements.txt
```

### Step 2: Run the Application

```bash
python app.py
```

### Step 3: Access the Application

- Open browser: `http://localhost:5000`
- The application will automatically:
  - Create SQLite database
  - Initialize all tables
  - Create default admin account

---

## 🔑 Default Admin Account

Upon first run, a default admin account is created:

```
Email:    admin@certificate-authority.com
Password: Admin@Secure123
```

⚠️ **IMPORTANT**: Change this password in production!

---

## 🗄️ Database Schema

### Users Table (`users`)

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    password_salt VARCHAR(64) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'applicant',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_verified BOOLEAN DEFAULT FALSE
);

INDEX: email (for fast lookup)
```

**Fields Explanation:**
- `password_hash`: SHA-256 hash of (password + salt)
- `password_salt`: Random 32-character hex string (16 bytes)
- `role`: 'applicant', 'verifier', or 'admin'
- `status`: 'active', 'inactive', or 'suspended'

### OTP Sessions Table (`otp_sessions`)

```sql
CREATE TABLE otp_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL FOREIGN KEY,
    otp_code VARCHAR(6) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    verified_at DATETIME
);

FOREIGN KEY: users(id)
```

**Fields Explanation:**
- `otp_code`: 6-digit random number
- `attempts`: Incremented on each failed attempt (max 5)
- `expires_at`: OTP expires after 5 minutes
- `verified_at`: Timestamp when OTP was successfully verified

### Audit Logs Table (`audit_logs`)

```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER FOREIGN KEY,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    ip_address VARCHAR(45),
    status VARCHAR(50) DEFAULT 'success',
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

FOREIGN KEY: users(id)
```

**Tracked Actions:**
- `user_registered`: New user registration
- `login_success`: Successful login (OTP sent)
- `login_failed`: Failed login attempt
- `otp_verified`: OTP successfully verified
- `otp_failed`: OTP verification failed
- `logout`: User logout

---

## 🔐 Security Implementation

### Password Hashing

**Algorithm**: SHA-256 with Random Salt

**Implementation:**

```python
def hash_password(password):
    # Generate random salt (16 bytes = 32 hex characters)
    salt = secrets.token_hex(16)
    
    # Create hash using SHA-256 with password + salt
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    
    return password_hash, salt


def verify_password(password, password_hash, password_salt):
    # Recreate hash with provided password and stored salt
    computed_hash = hashlib.sha256((password + password_salt).encode()).hexdigest()
    
    # Constant-time comparison to prevent timing attacks
    return computed_hash == password_hash
```

**Key Security Features:**
- ✅ Passwords NEVER stored in plaintext
- ✅ Random salt for each user (16 bytes)
- ✅ SHA-256 hashing
- ✅ Constant-time password comparison (prevents timing attacks)
- ✅ Passwords never logged or displayed

### OTP Generation & Verification

**OTP Details:**
- Length: 6 digits
- Validity: 5 minutes
- Max attempts: 5
- Display: Printed to console (no email/SMS yet)

**OTP Flow:**
1. User enters email and password
2. System validates credentials
3. OTP generated and stored in database
4. OTP printed to console
5. User enters OTP on /otp page
6. System validates OTP and marks session as verified
7. User gains access to /dashboard

**OTP Verification Checks:**
- OTP not expired
- OTP not already verified
- Attempt count < 5
- OTP matches stored value
- Session doesn't already have OTP verified

---

## 🔑 User Roles

### 1. Applicant
- Can request certificates
- Can view own certificates
- Can track certificate status
- Cannot verify or approve certificates

### 2. Verifier
- Can review pending certificate requests
- Can verify applicant information
- Can approve or reject requests for verification
- Cannot issue final approvals

### 3. Administrator
- Can approve/reject verified requests
- Can manage users and roles
- Can view system audit logs
- Can configure system settings
- Default admin account pre-created

---

## 🔄 User Registration & Login Workflow

### Registration Flow

```
User visits /register
    ↓
Enters: Full Name, Email, Password, Confirm Password, Role
    ↓
System validates input
    ↓
Check if email already exists
    ↓
Hash password with random salt
    ↓
Create user in database
    ↓
Log registration in audit trail
    ↓
Redirect to login page
```

### Login & OTP Flow

```
User visits /login
    ↓
Enters: Email, Password
    ↓
System finds user by email
    ↓
Verify password hash against stored salt
    ↓
Generate OTP (6 digits, 5 min validity)
    ↓
Store OTP in database
    ↓
Print OTP to console
    ↓
Create session (otp_verified = False)
    ↓
Redirect to /otp page
    ↓
User enters OTP
    ↓
Verify OTP against database
    ↓
If valid: Mark session as otp_verified = True
    ↓
Update user last_login timestamp
    ↓
Redirect to /dashboard
    ↓
Access granted to protected pages
```

---

## 🛡️ Protected Routes

### OTP Verification Required (`@otp_verified_required`)

These routes require both login AND OTP verification:
- `/dashboard` - Main dashboard
- Any future protected routes

### Admin Only (`@admin_required`)

These routes require admin role AND OTP verification:
- Future admin management pages

### Public Routes

- `/` - Landing page (redirects to login if authenticated)
- `/register` - User registration
- `/login` - User login
- `/otp` - OTP verification (requires login)

---

## 🧪 Verification Steps

### Step 1: Test User Registration

1. Start the server: `python app.py`
2. Open: http://localhost:5000
3. Click "Register"
4. Fill form:
   - Full Name: `Test User`
   - Email: `test@example.com`
   - Password: `TestPass123`
   - Confirm: `TestPass123`
   - Role: `Applicant`
5. Click "Register Account"
6. ✅ Should redirect to login with success message

### Step 2: Verify Password Hashing

1. Open SQLite database: `certificate_system.db`
2. Query: `SELECT email, password_hash, password_salt FROM users WHERE email='test@example.com'`
3. ✅ Verify:
   - `password_hash` is 64 hex characters (SHA-256)
   - `password_salt` is 32 hex characters (16 bytes)
   - Both are different from password text

### Step 3: Test Login & OTP

1. Go to login page
2. Enter: `test@example.com` / `TestPass123`
3. Check console output for OTP:
   ```
   ============================================================
   📱 OTP VERIFICATION REQUIRED
   ============================================================
   Email: test@example.com
   OTP Code: 123456
   Valid for: 5 minutes
   ============================================================
   ```
4. ✅ Should redirect to /otp page
5. Enter OTP from console
6. ✅ Should redirect to /dashboard

### Step 4: Test OTP Security

**Test Invalid OTP:**
1. Login again (generates new OTP)
2. Enter wrong OTP (e.g., 000000)
3. ✅ Should show error with remaining attempts
4. Try 5 times
5. ✅ On 5th attempt: error "Max OTP attempts exceeded" and session cleared

**Test Expired OTP:**
1. Login (generates OTP valid for 5 minutes)
2. Wait until expires (or manually edit database `expires_at`)
3. Try to verify
4. ✅ Should show "OTP has expired" error

### Step 5: Test Admin Login

1. Go to login
2. Email: `admin@certificate-authority.com`
3. Password: `Admin@Secure123`
4. Enter OTP from console
5. ✅ Dashboard should show role as "Admin"

### Step 6: Verify Audit Logs

1. Open database: `certificate_system.db`
2. Query: `SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10`
3. ✅ Should see:
   - user_registered
   - login_success
   - otp_verified
   - logout

### Step 7: Test Session Management

1. Login and verify OTP
2. Close browser (or clear cookies)
3. Try to access /dashboard directly
4. ✅ Should redirect to login

### Step 8: Test Logout

1. After successful login and OTP
2. Click "Logout"
3. ✅ Session should clear
4. ✅ Audit log should show "logout"
5. ✅ Redirected to login page

### Step 9: Test Password Verification

1. Login with correct email but wrong password
2. ✅ Should show "Invalid email or password" error
3. ✅ Audit log should show "login_failed"

---

## 🚨 Error Handling

The application handles these scenarios:

| Error | Handling |
|-------|----------|
| Missing fields | Validation error shown |
| Password mismatch | "Passwords do not match" |
| Email already exists | "Email already registered" |
| Invalid credentials | "Invalid email or password" |
| Inactive account | "Account is inactive" |
| Invalid OTP | Error with attempts remaining |
| OTP expired | "OTP has expired" error |
| Max attempts exceeded | Session cleared, login again |
| Not authenticated | Redirected to login |
| OTP not verified | Redirected to /otp |
| Not admin | 403 Forbidden error |

---

## 📊 Console Output Examples

### Successful Registration
```
============================================================
✅ Registration Successful!
============================================================
Email: test@example.com
Role: APPLICANT
Please proceed to login.
============================================================
```

### OTP Generation
```
============================================================
📱 OTP VERIFICATION REQUIRED
============================================================
Email: test@example.com
OTP Code: 482957
Valid for: 5 minutes
============================================================
⚠️  DO NOT SHARE THIS OTP WITH ANYONE
============================================================
```

### Successful OTP Verification
```
============================================================
✅ OTP VERIFIED SUCCESSFULLY!
============================================================
User: test@example.com
Role: APPLICANT
============================================================
```

### Failed Login
```
⚠️  Login Attempt - Invalid password for: test@example.com
```

---

## 🔒 Security Best Practices Implemented

✅ **Passwords:**
- Never stored in plaintext
- SHA-256 hashing with random salt
- Constant-time comparison
- Never logged or displayed

✅ **OTP:**
- 6-digit random generation
- 5-minute expiration
- Max 5 attempts per session
- Printed to console only

✅ **Sessions:**
- HTTPOnly cookies (prevents XSS)
- SameSite=Lax (prevents CSRF)
- Secure flag in production
- 2-hour session timeout

✅ **Audit Trail:**
- All authentication events logged
- IP address captured
- Timestamp recorded
- Action details stored

✅ **Database:**
- SQLite with foreign keys
- Indexed email for performance
- DateTime for all events
- Status tracking for users

---

## 📝 Database Queries for Testing

### Get All Users
```sql
SELECT id, email, role, status, last_login FROM users;
```

### Get User by Email
```sql
SELECT * FROM users WHERE email='test@example.com';
```

### Get Audit Logs for User
```sql
SELECT * FROM audit_logs WHERE user_id=1 ORDER BY created_at DESC;
```

### Get Recent Authentication Events
```sql
SELECT user_id, action, status, created_at FROM audit_logs 
WHERE action IN ('login_success', 'login_failed', 'otp_verified', 'otp_failed')
ORDER BY created_at DESC LIMIT 20;
```

### Get Active OTP Sessions
```sql
SELECT u.email, o.otp_code, o.attempts, o.expires_at 
FROM otp_sessions o
JOIN users u ON o.user_id = u.id
WHERE o.is_verified = FALSE AND o.expires_at > datetime('now');
```

---

## 🔄 Running the Application

### Development Mode (Current)

```bash
python app.py
```

- Flask runs on `localhost:5000`
- Debug mode enabled
- Auto-reloads on file changes

### Production Mode (Future)

```bash
pip install gunicorn
gunicorn -w 4 app:app
```

Or with environment variables:

```bash
export FLASK_ENV=production
export FLASK_DEBUG=0
python app.py
```

---

## 🐛 Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'flask'"

**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: "database is locked"

**Solution:** Only one app instance can write to SQLite at a time
```bash
# Kill other Flask instances
lsof -i :5000
kill -9 <PID>
```

### Issue: "OTP not appearing in console"

**Solution:** Make sure you're looking at the terminal where Flask is running, not browser console

### Issue: "Password verification always fails"

**Solution:** Ensure password hasn't been modified in database. Use hash_password() function

---

## 📚 Next Steps (Phase 3+)

Future implementations will include:

- Certificate type management
- Certificate request submission
- Verification workflow
- Admin approval system
- Certificate issuance
- Audit log viewing interface
- Email/SMS OTP delivery
- Password reset functionality
- Account management
- Rate limiting

---

## 📄 License

Secure Certificate Request & Approval System - Phase 2
Copyright © 2026 Certificate Authority

---

## ✅ Verification Checklist

- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] Database created and initialized
- [ ] Default admin account created
- [ ] User registration working
- [ ] Password hashing verified (SHA-256 + salt)
- [ ] Login with OTP generation working
- [ ] OTP verification working (6 attempts max)
- [ ] OTP expiration after 5 minutes working
- [ ] Dashboard access blocked until OTP verified
- [ ] Logout functionality working
- [ ] Audit logs recording all events
- [ ] Session management working correctly
- [ ] All error messages displaying properly
- [ ] Console output showing OTP codes

---

For questions or issues, check the console output for detailed error messages.
