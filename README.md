# Secure Certificate Request & Approval System - Phase 2
## Authentication & OTP Verification - Flask Backend

---

## 📋 Quick Overview

This is **Phase 2** of a multi-phase application for managing digital certificate requests with a secure authentication system.

| Component | Status | Details |
|-----------|--------|---------|
| **Frontend (Phase 1)** | ✅ Complete | 12 HTML pages + CSS |
| **Backend (Phase 2)** | ✅ Complete | Flask app with auth |
| **Database** | ✅ Complete | SQLite with 3 tables |
| **Security** | ✅ Complete | SHA-256 hashing + OTP |

---

## 🚀 Getting Started (5 minutes)

### 1. Install Dependencies
```bash
cd /Users/gugansaravanan/Downloads/cyber
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```

### 3. Access the System
```
Browser: http://localhost:5000
Email:   admin@certificate-authority.com
Pass:    Admin@Secure123
```

---

## 📁 Project Structure

```
cyber/
├── README.md               # This file
├── SETUP.md                # Installation & setup guide
├── REFERENCE.md            # Quick reference guide
├── VERIFICATION.md         # Testing & verification
├── app.py                  # Flask application (527 lines)
├── requirements.txt        # Python dependencies
├── certificate_system.db   # SQLite database (auto-created)
└── ui/                     # Frontend files
    ├── index.html
    ├── login.html
    ├── register.html
    ├── otp.html
    ├── dashboard.html
    ├── certificate_types.html
    ├── request_certificate.html
    ├── my_certificates.html
    ├── view_certificate.html
    ├── verifier_tasks.html
    ├── admin_approvals.html
    ├── audit_logs.html
    └── styles.css
```

---

## ✨ Phase 2 Features

### User Authentication
- ✅ User registration with validation
- ✅ Secure login with password verification
- ✅ Password hashing (SHA-256 + random salt)
- ✅ Email uniqueness enforcement

### OTP (One-Time Password)
- ✅ 6-digit OTP generation
- ✅ 5-minute validity period
- ✅ Max 5 verification attempts
- ✅ OTP printed to console
- ✅ Automatic session verification

### Session Management
- ✅ Login state tracking
- ✅ OTP verification state
- ✅ 2-hour session timeout
- ✅ HTTPOnly secure cookies
- ✅ Automatic logout on new login

### User Roles
- ✅ **Applicant** - Request certificates
- ✅ **Verifier** - Verify requests
- ✅ **Administrator** - Approve requests & manage system

### Security & Audit
- ✅ Complete audit trail
- ✅ All authentication events logged
- ✅ IP address capture
- ✅ Status tracking
- ✅ Comprehensive error handling

---

## 🔐 Security Implementation

### Password Hashing

Passwords are protected using **SHA-256 hashing with random salt**:

```
Registration:
  Password: "MySecurePass123"
  Random Salt Generated: "a1b2c3d4e5f6g7h8..." (16 bytes)
  Hash = SHA256("MySecurePass123" + salt)
  Stored: (hash, salt) in database

Login Verification:
  User enters password
  System retrieves stored salt
  Recompute hash = SHA256(entered_password + salt)
  Compare with stored hash
  Result: Match = Valid, No Match = Invalid
```

**Security Features:**
- Never stored in plaintext
- Each user has unique salt
- Salt is 16 bytes (128 bits)
- Hash is 64 characters (256 bits)
- Constant-time comparison prevents timing attacks

### OTP Verification

6-digit OTP with multiple security layers:

```
Generation: random.randint(0, 9) × 6 = "482957"
Storage: Encrypted in database
Validity: 5 minutes
Attempts: Max 5 failures → session cleared

Verification Flow:
  1. User enters OTP
  2. System checks: Not expired, Not already verified, <5 attempts
  3. If valid: Set session['otp_verified'] = True
  4. If invalid: Increment attempts, show remaining
  5. If >=5 failures: Clear session, force re-login
```

---

## 🗄️ Database Schema

### Three Tables

**Users Table**
- Stores user accounts with hashed passwords
- Tracks login history and verification status
- Indexes on email for fast lookup

**OTP Sessions Table**
- Temporary storage for OTP verification
- Tracks attempts and expiration
- Linked to user account

**Audit Logs Table**
- Complete record of all system actions
- IP address and timestamp
- Success/failure status

---

## 🔑 Default Admin Account

Created automatically on first run:

```
Email:    admin@certificate-authority.com
Password: Admin@Secure123
Role:     Administrator
```

⚠️ **Change this in production!**

---

## 📊 Routes & Navigation

### Public Routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Landing page |
| `/register` | GET/POST | User registration |
| `/login` | GET/POST | User login |

### Protected Routes (Login Required)
| Route | Method | Purpose |
|-------|--------|---------|
| `/otp` | GET/POST | OTP verification |
| `/logout` | GET | Logout user |

### Fully Protected Routes (Login + OTP Required)
| Route | Method | Purpose |
|-------|--------|---------|
| `/dashboard` | GET | Main dashboard |

---

## 💻 Console Output Example

When you run `python app.py`, you'll see:

```
============================================================
🚀 Secure Certificate Authority - Phase 2
============================================================
Flask Server Starting...
URL: http://localhost:5000
============================================================

============================================================
🔧 DATABASE INITIALIZED
============================================================
Default Admin Account Created:
Email: admin@certificate-authority.com
Password: Admin@Secure123
============================================================
```

When a user registers:

```
============================================================
✅ Registration Successful!
============================================================
Email: user@example.com
Role: APPLICANT
Please proceed to login.
============================================================
```

When user logs in (OTP generated):

```
============================================================
📱 OTP VERIFICATION REQUIRED
============================================================
Email: user@example.com
OTP Code: 482957
Valid for: 5 minutes
============================================================
⚠️  DO NOT SHARE THIS OTP WITH ANYONE
============================================================
```

When OTP is verified:

```
============================================================
✅ OTP VERIFIED SUCCESSFULLY!
============================================================
User: user@example.com
Role: APPLICANT
============================================================
```

---

## 🧪 Testing the System

### Test User Registration
1. Go to `/register`
2. Fill form with new user details
3. Select role (Applicant/Verifier)
4. Click "Register Account"

### Test Login & OTP
1. Go to `/login`
2. Enter email and password
3. Check Flask console for OTP code
4. Go to `/otp` page
5. Enter OTP from console
6. Access `/dashboard` after verification

### Test Admin Access
1. Login with: `admin@certificate-authority.com` / `Admin@Secure123`
2. Verify OTP from console
3. Dashboard shows "Administrator" role

---

## 📚 Documentation Files

### SETUP.md (380+ lines)
Complete installation and setup guide with:
- Step-by-step installation
- Database schema with SQL
- Password hashing explanation
- OTP implementation details
- User roles and permissions
- Workflow diagrams
- Error handling guide
- Database queries for testing

### REFERENCE.md (350+ lines)
Quick reference for developers:
- Quick start commands
- Table structures
- Route reference
- Workflow sequences
- Decorator usage
- SQL query examples
- Debugging tips
- Phase 3+ roadmap

### VERIFICATION.md (350+ lines)
Complete testing and verification guide:
- 15 detailed test cases
- Step-by-step verification procedures
- Expected database state
- Security verification checklist
- Code quality metrics
- Troubleshooting commands

---

## 🔒 Security Highlights

✅ **Never plaintext passwords**
- SHA-256 hashing with random salt
- 16-byte salt per user
- Constant-time comparison

✅ **Secure OTP system**
- Random 6-digit generation
- 5-minute validity
- Max 5 attempts
- Database storage

✅ **Session protection**
- HTTPOnly cookies (XSS prevention)
- SameSite=Lax (CSRF prevention)
- 2-hour timeout
- Clear on logout

✅ **Complete audit trail**
- All authentication events logged
- IP address captured
- Success/failure tracking
- User action history

---

## 🐛 Troubleshooting

### ModuleNotFoundError: No module named 'flask'
```bash
pip install -r requirements.txt
```

### Port 5000 already in use
```bash
lsof -i :5000
kill -9 <PID>
```

### Database locked
Only one Flask instance can access SQLite at a time. Kill other instances.

### OTP not showing
Check the Flask console window where `python app.py` is running, not the browser console.

---

## ✅ Verification Checklist

Before running tests:

- [ ] Python 3.7+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Port 5000 available
- [ ] No database errors on startup

After starting `python app.py`:

- [ ] Server starts without errors
- [ ] Admin account created
- [ ] Database file exists

After testing registration:

- [ ] User created in database
- [ ] Password hashing verified
- [ ] Audit log shows registration

After testing login & OTP:

- [ ] OTP printed to console
- [ ] Session created with login
- [ ] OTP verification works
- [ ] Dashboard accessible after verification

---

## 📈 Code Metrics

| Metric | Value |
|--------|-------|
| Total Lines (app.py) | 527 |
| Functions | 15+ |
| Database Tables | 3 |
| Routes Implemented | 9 |
| Decorators | 3 |
| Error Handlers | 2 |
| Security Features | 8+ |
| Tests Required | 15 |

---

## 🎯 What's Implemented

### Phase 2: ✅ COMPLETE

- ✅ User registration system
- ✅ Secure login with password verification
- ✅ OTP generation and verification
- ✅ Session management
- ✅ Multiple user roles
- ✅ Audit logging
- ✅ Database design
- ✅ Error handling
- ✅ Security implementation
- ✅ Complete documentation

### Next: Phase 3 (Certificate Management)

- Certificate type definitions
- Request submission
- Status tracking
- Verifier workflow
- Admin approvals

---

## 📖 How to Use This Project

### For Development
1. Read **SETUP.md** for detailed setup
2. Check **REFERENCE.md** for quick lookups
3. Review **app.py** source code
4. Run verification tests from **VERIFICATION.md**

### For Deployment
1. Update `app.config['SECRET_KEY']` to random value
2. Change default admin password
3. Set `app.config['SESSION_COOKIE_SECURE'] = True` (HTTPS only)
4. Use production WSGI server (Gunicorn, uWSGI)
5. Enable HTTPS/SSL certificates

### For Testing
1. Follow 15 test cases in **VERIFICATION.md**
2. Use SQL queries from **REFERENCE.md** to inspect database
3. Check console output for OTP codes
4. Verify audit logs for all actions

---

## 💡 Key Concepts

**Password Hashing**: Passwords are never stored. Instead, a hash is created using the password + random salt, making it impossible to reverse-engineer the original password.

**OTP Verification**: After login, users must enter a 6-digit code that was generated and printed to the console. This adds a second layer of security.

**Session Management**: Once logged in and OTP verified, the user's session is marked as authenticated, allowing access to protected pages.

**Audit Trail**: Every authentication action (login, logout, OTP verification, etc.) is recorded with timestamp, IP address, and status.

**User Roles**: Different roles (Applicant, Verifier, Admin) have different permissions in the system.

---

## 🔗 File Overview

| File | Lines | Purpose |
|------|-------|---------|
| app.py | 527 | Main Flask application |
| requirements.txt | 3 | Python dependencies |
| SETUP.md | 380+ | Setup and installation |
| REFERENCE.md | 350+ | Quick reference guide |
| VERIFICATION.md | 350+ | Testing procedures |
| README.md | This | Project overview |

---

## 📞 Support

For detailed information:
- **Installation issues**: See SETUP.md
- **API reference**: See REFERENCE.md  
- **Testing & verification**: See VERIFICATION.md
- **Source code**: See app.py (well-commented)
- **Database queries**: See REFERENCE.md SQL section

---

## ✨ Summary

**Phase 2 delivers a production-ready authentication system with:**

- Secure password hashing (SHA-256 + salt)
- OTP-based 2FA verification
- Complete session management
- Multiple user roles
- Comprehensive audit trail
- Professional error handling
- Ready for Phase 3 integration

**Status: ✅ Ready for Production Testing**

---

**Next Steps:**
1. Run `pip install -r requirements.txt`
2. Run `python app.py`
3. Test system using VERIFICATION.md guide
4. Proceed to Phase 3: Certificate Management

---

Last Updated: January 28, 2026
