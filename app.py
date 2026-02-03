"""
Secure Certificate Request & Approval System

"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, send_file
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import secrets
import random
import base64
from datetime import datetime, timedelta
from functools import wraps
from bson.objectid import ObjectId
import io
import pyotp  # TOTP-based MFA
import qrcode  # QR Code generation for authenticator apps
from io import BytesIO

# Load environment variables from .env file
load_dotenv()

# ============================================
# Flask Configuration
# ============================================

app = Flask(__name__, template_folder='ui', static_folder='ui')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Register Jinja filters for templates
@app.template_filter('b64encode')
def b64encode_filter(s):
    """Base64 encode filter for Jinja templates"""
    try:
        if isinstance(s, ObjectId):
            s = str(s)
        return base64.b64encode(str(s).encode()).decode()
    except:
        return s

# ============================================
# MongoDB Configuration
# ============================================

MONGODB_URI = os.getenv('MONGODB_URI')

if not MONGODB_URI:
    print("❌ ERROR: MONGODB_URI not found in .env file")
    print("Please create .env file with MONGODB_URI variable")
    exit(1)

try:
    # Add timeout to prevent hanging if MongoDB is not available
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    db = mongo_client['certificate_authority']
    
    # Initialize collections
    users_collection = db['users']
    otp_sessions_collection = db['otp_sessions']
    audit_logs_collection = db['audit_logs']
    certificate_requests_collection = db['certificate_requests']
    
    # Create indexes for better performance
    users_collection.create_index('email', unique=True)
    otp_sessions_collection.create_index('user_id')
    audit_logs_collection.create_index('user_id')
    audit_logs_collection.create_index('created_at')
    certificate_requests_collection.create_index('applicant_id')
    certificate_requests_collection.create_index('status')
    
    print("✅ MongoDB Connected Successfully")
except PyMongoError as e:
    print(f"❌ MongoDB Connection Error: {str(e)}")
    print(f"   Check your MONGODB_URI in .env file")
    exit(1)

# ============================================
# Database Model Functions (MongoDB)
# ============================================

def create_user(full_name, email, password_hash, password_salt, role='applicant', status='active'):
    """Create a new user in MongoDB"""
    try:
        user_doc = {
            'full_name': full_name,
            'email': email,
            'password_hash': password_hash,
            'password_salt': password_salt,
            'role': role,
            'status': status,
            'created_at': datetime.utcnow(),
            'last_login': None,
            'is_verified': False
        }
        result = users_collection.insert_one(user_doc)
        return result.inserted_id
    except Exception as e:
        print(f"❌ Error creating user: {str(e)}")
        return None


def get_user_by_email(email):
    """Get user by email"""
    try:
        return users_collection.find_one({'email': email})
    except Exception as e:
        print(f"❌ Error getting user by email: {str(e)}")
        return None


def get_user_by_id(user_id):
    """Get user by ID (converts string to ObjectId)"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        return users_collection.find_one({'_id': user_id})
    except Exception as e:
        print(f"❌ Error getting user by ID: {str(e)}")
        return None


def update_user_last_login(user_id):
    """Update user's last login timestamp"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        users_collection.update_one(
            {'_id': user_id},
            {'$set': {'last_login': datetime.utcnow()}}
        )
    except Exception as e:
        print(f"❌ Error updating last login: {str(e)}")


def create_otp_session(user_id, otp_code, expires_at):
    """Create an OTP session"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        
        otp_doc = {
            'user_id': user_id,
            'otp_code': otp_code,
            'is_verified': False,
            'attempts': 0,
            'created_at': datetime.utcnow(),
            'expires_at': expires_at,
            'verified_at': None
        }
        result = otp_sessions_collection.insert_one(otp_doc)
        return result.inserted_id
    except Exception as e:
        print(f"❌ Error creating OTP session: {str(e)}")
        return None


def get_latest_otp_session(user_id):
    """Get the latest OTP session for a user"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        
        return otp_sessions_collection.find_one(
            {'user_id': user_id},
            sort=[('created_at', -1)]
        )
    except Exception as e:
        print(f"❌ Error getting OTP session: {str(e)}")
        return None


def update_otp_session(otp_id, is_verified=False, attempts=None, verified_at=None):
    """Update OTP session status"""
    try:
        if isinstance(otp_id, str):
            otp_id = ObjectId(otp_id)
        
        update_dict = {}
        if is_verified:
            update_dict['is_verified'] = True
            update_dict['verified_at'] = datetime.utcnow()
        if attempts is not None:
            update_dict['attempts'] = attempts
        
        otp_sessions_collection.update_one(
            {'_id': otp_id},
            {'$set': update_dict}
        )
    except Exception as e:
        print(f"❌ Error updating OTP session: {str(e)}")


def cleanup_expired_otp_sessions():
    """Remove expired OTP sessions (older than 10 minutes)"""
    try:
        cutoff_time = datetime.utcnow() - timedelta(minutes=10)
        result = otp_sessions_collection.delete_many({
            'created_at': {'$lt': cutoff_time},
            'is_verified': False
        })
        if result.deleted_count > 0:
            print(f"🧹 Cleaned up {result.deleted_count} expired OTP sessions")
    except Exception as e:
        print(f"⚠️  Error cleaning up OTP sessions: {str(e)}")


def validate_session_timeout(user_id):
    """Check if user session is still valid and not expired"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        
        # Get latest OTP session
        otp_session = otp_sessions_collection.find_one(
            {'user_id': user_id},
            sort=[('created_at', -1)]
        )
        
        if not otp_session:
            return False
        
        # Check if OTP is expired
        if datetime.utcnow() > otp_session['expires_at']:
            return False
        
        # Check if OTP is verified
        if not otp_session.get('is_verified'):
            return False
        
        return True
    except Exception as e:
        print(f"❌ Error validating session: {str(e)}")
        return False


def create_audit_log(user_id, action, resource=None, status='success', details=None):
    """Create an audit log entry with comprehensive tracking"""
    try:
        if user_id and isinstance(user_id, str):
            try:
                user_id = ObjectId(user_id)
            except:
                user_id = None
        
        log_doc = {
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'ip_address': get_client_ip(),
            'status': status,
            'details': details,
            'created_at': datetime.utcnow(),
            'user_agent': request.headers.get('User-Agent', 'Unknown')
        }
        audit_logs_collection.insert_one(log_doc)
    except Exception as e:
        print(f"❌ Error creating audit log: {str(e)}")


def get_audit_logs(limit=100, skip=0, user_id=None, action=None):
    """Retrieve audit logs with optional filtering"""
    try:
        query = {}
        if user_id:
            query['user_id'] = ObjectId(user_id) if isinstance(user_id, str) else user_id
        if action:
            query['action'] = action
        
        logs = list(
            audit_logs_collection.find(query)
            .sort('created_at', -1)
            .skip(skip)
            .limit(limit)
        )
        
        # Convert ObjectIds to strings for JSON serialization
        for log in logs:
            if log.get('user_id'):
                log['user_id'] = str(log['user_id'])
            log['_id'] = str(log['_id'])
        
        return logs
    except Exception as e:
        print(f"❌ Error retrieving audit logs: {str(e)}")
        return []


def get_audit_logs_by_date_range(start_date, end_date, limit=100):
    """Retrieve audit logs within a specific date range"""
    try:
        logs = list(
            audit_logs_collection.find({
                'created_at': {'$gte': start_date, '$lte': end_date}
            })
            .sort('created_at', -1)
            .limit(limit)
        )
        
        # Convert ObjectIds to strings
        for log in logs:
            if log.get('user_id'):
                log['user_id'] = str(log['user_id'])
            log['_id'] = str(log['_id'])
        
        return logs
    except Exception as e:
        print(f"❌ Error retrieving audit logs by date: {str(e)}")
        return []


def get_user_audit_trail(user_id, limit=50):
    """Get complete audit trail for a specific user"""
    try:
        user_obj_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        logs = list(
            audit_logs_collection.find({'user_id': user_obj_id})
            .sort('created_at', -1)
            .limit(limit)
        )
        
        # Convert ObjectIds
        for log in logs:
            log['user_id'] = str(log['user_id'])
            log['_id'] = str(log['_id'])
        
        return logs
    except Exception as e:
        print(f"❌ Error retrieving user audit trail: {str(e)}")
        return []


def get_action_statistics():
    """Get statistics on audit log actions"""
    try:
        stats = list(audit_logs_collection.aggregate([
            {'$group': {
                '_id': '$action',
                'count': {'$sum': 1},
                'successes': {'$sum': {'$cond': [{'$eq': ['$status', 'success']}, 1, 0]}},
                'failures': {'$sum': {'$cond': [{'$eq': ['$status', 'failure']}, 1, 0]}}
            }},
            {'$sort': {'count': -1}}
        ]))
        return list(stats)
    except Exception as e:
        print(f"❌ Error getting action statistics: {str(e)}")
        return []


def create_certificate_request(applicant_id, certificate_type, purpose):
    """Create a new certificate request"""
    try:
        if isinstance(applicant_id, str):
            applicant_id = ObjectId(applicant_id)
        
        cert_doc = {
            'applicant_id': applicant_id,
            'certificate_type': certificate_type,
            'purpose': purpose,
            'status': 'pending',
            'rejection_reason': None,
            'created_at': datetime.utcnow(),
            'verified_at': None,
            'approved_at': None,
            'verifier_id': None,
            'admin_id': None,
            # Phase 10: Expiry & Revocation
            'expiry_date': None,  # Set when approved (1 year from approval)
            'is_revoked': False,
            'revocation_date': None,
            'revocation_reason': None,
            'revoked_by_admin_id': None
        }
        result = certificate_requests_collection.insert_one(cert_doc)
        return result.inserted_id
    except Exception as e:
        print(f"❌ Error creating certificate request: {str(e)}")
        return None


def get_user_certificate_requests(applicant_id):
    """Get all certificate requests for a user"""
    try:
        if isinstance(applicant_id, str):
            applicant_id = ObjectId(applicant_id)
        
        return list(certificate_requests_collection.find({'applicant_id': applicant_id}).sort('created_at', -1))
    except Exception as e:
        print(f"❌ Error getting certificate requests: {str(e)}")
        return []


def get_pending_certificate_requests():
    """Get all pending certificate requests (for verifiers)"""
    try:
        requests = list(certificate_requests_collection.find({'status': 'pending'}).sort('created_at', -1))
        
        # Populate applicant information for each request
        for req in requests:
            if 'applicant_id' in req:
                applicant = users_collection.find_one({'_id': ObjectId(req['applicant_id'])})
                if applicant:
                    req['applicant_name'] = applicant.get('full_name', 'Unknown')
                    req['applicant_email'] = applicant.get('email', 'Unknown')
                else:
                    req['applicant_name'] = 'Unknown'
                    req['applicant_email'] = 'Unknown'
            else:
                req['applicant_name'] = 'Unknown'
                req['applicant_email'] = 'Unknown'
        
        return requests
    except Exception as e:
        print(f"❌ Error getting pending requests: {str(e)}")
        return []


def get_verified_certificate_requests():
    """Get all verified certificate requests (for admin approval)"""
    try:
        requests = list(certificate_requests_collection.find({'status': 'verified'}).sort('created_at', -1))
        
        # Populate applicant information for each request
        for req in requests:
            if 'applicant_id' in req:
                applicant = users_collection.find_one({'_id': ObjectId(req['applicant_id'])})
                if applicant:
                    req['applicant_name'] = applicant.get('full_name', 'Unknown')
                    req['applicant_email'] = applicant.get('email', 'Unknown')
                else:
                    req['applicant_name'] = 'Unknown'
                    req['applicant_email'] = 'Unknown'
            else:
                req['applicant_name'] = 'Unknown'
                req['applicant_email'] = 'Unknown'
        
        return requests
    except Exception as e:
        print(f"❌ Error getting verified requests: {str(e)}")
        return []


# ============================================
# Certificate Expiry & Revocation Functions (Phase 10)
# ============================================

def check_certificate_status(cert_id):
    """
    Check if certificate is valid (not expired and not revoked)
    
    Args:
        cert_id: MongoDB ObjectId of certificate
        
    Returns:
        dict: {
            'is_valid': bool,
            'reason': str (if invalid),
            'status': str (active/expired/revoked),
            'expiry_date': datetime (if applicable)
        }
    """
    try:
        cert = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert:
            return {'is_valid': False, 'reason': 'Certificate not found', 'status': 'not_found'}
        
        # Check revocation status
        if cert.get('is_revoked', False):
            return {
                'is_valid': False,
                'reason': f"Certificate revoked on {cert.get('revocation_date')}. Reason: {cert.get('revocation_reason', 'No reason provided')}",
                'status': 'revoked',
                'revocation_date': cert.get('revocation_date')
            }
        
        # Check expiration status
        expiry_date = cert.get('expiry_date')
        if expiry_date and isinstance(expiry_date, datetime):
            if datetime.utcnow() > expiry_date:
                return {
                    'is_valid': False,
                    'reason': f'Certificate expired on {expiry_date.strftime("%Y-%m-%d %H:%M:%S")}',
                    'status': 'expired',
                    'expiry_date': expiry_date
                }
        
        return {
            'is_valid': True,
            'status': 'active',
            'expiry_date': expiry_date,
            'reason': None
        }
    except Exception as e:
        print(f"❌ Error checking certificate status: {str(e)}")
        return {'is_valid': False, 'reason': str(e), 'status': 'error'}


def revoke_certificate(cert_id, admin_id, revocation_reason='No reason provided'):
    """
    Revoke a certificate (admin-only action)
    
    Args:
        cert_id: MongoDB ObjectId of certificate to revoke
        admin_id: ObjectId of admin performing revocation
        revocation_reason: Reason for revocation
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if isinstance(cert_id, str):
            cert_id = ObjectId(cert_id)
        if isinstance(admin_id, str):
            admin_id = ObjectId(admin_id)
        
        cert = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert:
            print(f"❌ Certificate {cert_id} not found")
            return False
        
        if cert.get('is_revoked', False):
            print(f"⚠️  Certificate {cert_id} already revoked")
            return False
        
        # Update certificate with revocation info
        result = certificate_requests_collection.update_one(
            {'_id': cert_id},
            {'$set': {
                'is_revoked': True,
                'revocation_date': datetime.utcnow(),
                'revocation_reason': revocation_reason,
                'revoked_by_admin_id': admin_id
            }}
        )
        
        if result.modified_count > 0:
            print(f"✅ Certificate {cert_id} revoked successfully")
            return True
        return False
    except Exception as e:
        print(f"❌ Error revoking certificate: {str(e)}")
        return False


def get_revoked_certificates():
    """
    Get all revoked certificates (for admin dashboard)
    
    Returns:
        list: List of revoked certificate documents
    """
    try:
        return list(certificate_requests_collection.find({'is_revoked': True}).sort('revocation_date', -1))
    except Exception as e:
        print(f"❌ Error getting revoked certificates: {str(e)}")
        return []


def get_expiring_certificates(days=30):
    """
    Get certificates expiring soon (for admin alerts)
    
    Args:
        days: Number of days to check ahead (default: 30)
        
    Returns:
        list: List of certificates expiring within specified days
    """
    try:
        now = datetime.utcnow()
        future_date = now + timedelta(days=days)
        
        return list(certificate_requests_collection.find({
            'expiry_date': {'$lte': future_date, '$gte': now},
            'is_revoked': False,
            'status': 'approved'
        }).sort('expiry_date', 1))
    except Exception as e:
        print(f"❌ Error getting expiring certificates: {str(e)}")
        return []


def get_certificate_statistics():
    """
    Get certificate statistics (active, expired, revoked)
    
    Returns:
        dict: Statistics about certificates
    """
    try:
        now = datetime.utcnow()
        
        # Count active certificates
        active_count = certificate_requests_collection.count_documents({
            'is_revoked': False,
            'expiry_date': {'$gt': now},
            'status': 'approved'
        })
        
        # Count expired certificates
        expired_count = certificate_requests_collection.count_documents({
            'is_revoked': False,
            'expiry_date': {'$lte': now},
            'status': 'approved'
        })
        
        # Count revoked certificates
        revoked_count = certificate_requests_collection.count_documents({
            'is_revoked': True
        })
        
        # Count pending/verified
        pending_count = certificate_requests_collection.count_documents({
            'status': 'pending'
        })
        verified_count = certificate_requests_collection.count_documents({
            'status': 'verified'
        })
        
        return {
            'active': active_count,
            'expired': expired_count,
            'revoked': revoked_count,
            'pending': pending_count,
            'verified': verified_count,
            'total_approved': active_count + expired_count + revoked_count
        }
    except Exception as e:
        print(f"❌ Error getting certificate statistics: {str(e)}")
        return {}


# ============================================
# Utility Functions
# ============================================

# NIST SP 800-63B Common Breached Passwords List
COMMON_PASSWORDS = {
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    '1234567890', 'qwerty', 'qwerty123', 'letmein', 'welcome', 'welcome1',
    'admin', 'admin123', 'administrator', 'login', 'passw0rd', 'master',
    'hello', 'shadow', 'sunshine', 'princess', 'dragon', 'monkey', 'abc123',
    'football', 'baseball', 'soccer', 'hockey', 'batman', 'superman',
    'trustno1', 'iloveyou', 'starwars', 'whatever', 'freedom', 'mustang',
    'cheese', 'access', 'passwd', 'secret', 'test', 'test123', 'guest',
    'changeme', 'qazwsx', 'zxcvbn', 'asdfgh', 'asdf1234', 'qwer1234',
    '111111', '000000', '654321', '666666', '696969', '121212', '112233',
    'password1!', 'p@ssw0rd', 'p@ssword', 'pa$$word', 'passw0rd!',
    'certificate', 'security', 'secure123', 'admin@123', 'root', 'toor'
}


def validate_password_nist(password, email=None, full_name=None):
    """
    Validate password according to NIST SP 800-63B guidelines.
    
    NIST Guidelines:
    1. Minimum 8 characters (we use 12 for better security)
    2. Maximum 64+ characters allowed
    3. Check against common/breached passwords
    4. Check for context-specific words (email, name)
    5. Allow all printable characters including spaces
    6. NO complexity requirements (uppercase, numbers, special chars)
    
    Returns: (is_valid, error_message)
    """
    errors = []
    
    # Rule 1: Minimum length (NIST recommends 8, we use 12 for better security)
    if len(password) < 12:
        errors.append('Password must be at least 12 characters (NIST SP 800-63B)')
    
    # Rule 2: Maximum length (NIST recommends supporting at least 64)
    if len(password) > 128:
        errors.append('Password cannot exceed 128 characters')
    
    # Rule 3: Check against common/breached passwords
    if password.lower() in COMMON_PASSWORDS:
        errors.append('This password is too common and has been found in data breaches')
    
    # Rule 4: Check for repetitive/sequential patterns
    if len(set(password)) < 4:
        errors.append('Password contains too many repetitive characters')
    
    # Check for sequential characters (123456, abcdef)
    sequential_patterns = ['123456', '234567', '345678', '456789', '567890',
                          'abcdef', 'bcdefg', 'cdefgh', 'qwerty', 'asdfgh', 'zxcvbn']
    for pattern in sequential_patterns:
        if pattern in password.lower():
            errors.append('Password contains sequential characters')
            break
    
    # Rule 5: Check for context-specific words (email username, name)
    if email:
        email_local = email.split('@')[0].lower()
        if len(email_local) > 3 and email_local in password.lower():
            errors.append('Password should not contain your email address')
    
    if full_name:
        name_parts = full_name.lower().split()
        for part in name_parts:
            if len(part) > 3 and part in password.lower():
                errors.append('Password should not contain your name')
                break
    
    if errors:
        return False, ' | '.join(errors)
    
    return True, None


def hash_password(password):
    """
    Hash password with SHA-256 and random salt.
    Returns: (password_hash, salt)
    """
    print(f"\n{'='*60}")
    print("🔒 PASSWORD HASHING WITH SALT")
    print(f"{'='*60}")
    print(f"Password Length: {len(password)} characters")
    
    # Generate random salt
    salt = secrets.token_hex(16)
    print(f"✅ Salt Generated: {len(salt)} chars (hex)")
    print(f"   Salt: {salt[:40]}...")
    
    # Hash password with salt using SHA-256
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    print(f"✅ Password Hashed with SHA-256")
    print(f"   Hash: {password_hash[:60]}...")
    print(f"{'='*60}\n")
    
    return password_hash, salt


def verify_password(password, password_hash, password_salt):
    """Verify password against stored hash and salt"""
    computed_hash = hashlib.sha256((password + password_salt).encode()).hexdigest()
    return computed_hash == password_hash


def generate_otp(length=6):
    """Generate random OTP of specified length (default 6 digits)"""
    return ''.join(str(random.randint(0, 9)) for _ in range(length))


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


# ============================================
# TOTP MFA Functions (Authenticator App)
# ============================================

def generate_totp_secret():
    """
    Generate a random base32 secret for TOTP
    Used by authenticator apps (Google Authenticator, Authy, etc.)
    
    Returns: 32-character base32 secret
    """
    return pyotp.random_base32()


def get_totp_provisioning_uri(secret, email, issuer="SecureCertAuthority"):
    """
    Generate provisioning URI for QR code
    This URI is scanned by authenticator apps to add the account
    
    Args:
        secret: Base32 TOTP secret
        email: User's email (account name in app)
        issuer: App name shown in authenticator
    
    Returns: otpauth:// URI string
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify_totp_code(secret, code):
    """
    Verify a 6-digit TOTP code against the secret
    
    Args:
        secret: User's base32 TOTP secret
        code: 6-digit code from authenticator app
    
    Returns: True if valid, False otherwise
    
    Note: TOTP codes are valid for 30 seconds by default
          pyotp allows 1 code before/after for clock drift
    """
    if not secret or not code:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Allow 1 period before/after


def generate_totp_qr_code(provisioning_uri):
    """
    Generate QR code image for TOTP setup
    
    Args:
        provisioning_uri: otpauth:// URI from get_totp_provisioning_uri()
    
    Returns: Base64 encoded PNG image string
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding in HTML
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_base64}"


def update_user_mfa_secret(user_id, mfa_secret):
    """Store MFA secret for user"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        users_collection.update_one(
            {'_id': user_id},
            {'$set': {'mfa_secret': mfa_secret, 'mfa_enabled': False}}
        )
        return True
    except Exception as e:
        print(f"❌ Error updating MFA secret: {str(e)}")
        return False


def enable_user_mfa(user_id):
    """Enable MFA for user after successful verification"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        users_collection.update_one(
            {'_id': user_id},
            {'$set': {'mfa_enabled': True}}
        )
        return True
    except Exception as e:
        print(f"❌ Error enabling MFA: {str(e)}")
        return False


def disable_user_mfa(user_id):
    """Disable MFA for user"""
    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
        users_collection.update_one(
            {'_id': user_id},
            {'$set': {'mfa_enabled': False, 'mfa_secret': None}}
        )
        return True
    except Exception as e:
        print(f"❌ Error disabling MFA: {str(e)}")
        return False


# ============================================
# Encoding Functions (Phase 9)
# ============================================

def encode_cert_id(cert_id):
    """
    Encode certificate ID using Base64 for safe transmission
    
    Purpose: Safe transmission over HTTP (not encryption)
    Use: For displaying IDs in URLs/forms
    """
    try:
        if isinstance(cert_id, ObjectId):
            cert_id = str(cert_id)
        
        cert_id_bytes = cert_id.encode('utf-8')
        encoded_bytes = base64.b64encode(cert_id_bytes)
        encoded_str = encoded_bytes.decode('utf-8')
        
        return encoded_str
    except Exception as e:
        print(f"❌ Error encoding certificate ID: {str(e)}")
        return None


def decode_cert_id(encoded_id):
    """
    Decode Base64-encoded certificate ID
    
    Purpose: Convert transmitted ID back to original ObjectId
    Returns: ObjectId if valid, None if invalid encoding
    Raises: ValueError if encoded_id is not valid Base64
    """
    try:
        if not encoded_id:
            return None
        
        # Decode from Base64
        encoded_bytes = encoded_id.encode('utf-8')
        decoded_bytes = base64.b64decode(encoded_bytes)
        decoded_str = decoded_bytes.decode('utf-8')
        
        # Convert to ObjectId
        cert_id = ObjectId(decoded_str)
        
        return cert_id
    except Exception as e:
        print(f"⚠️  Invalid certificate ID encoding: {str(e)}")
        return None


def is_valid_encoded_id(encoded_id):
    """
    Check if encoded_id is valid without raising exceptions
    
    Purpose: Pre-flight validation before decoding
    Returns: True if valid, False otherwise
    """
    try:
        decoded = decode_cert_id(encoded_id)
        return decoded is not None
    except:
        return False


# ============================================
# Hybrid Encryption Functions (RSA + AES)
# ============================================

def get_rsa_private_key():
    """Load RSA private key from .env"""
    rsa_private_key_pem = os.getenv('RSA_PRIVATE_KEY')
    
    if not rsa_private_key_pem:
        raise ValueError("❌ RSA_PRIVATE_KEY not found in .env - Phase 6 setup incomplete")
    
    # Convert \\n back to newlines
    rsa_private_key_pem = rsa_private_key_pem.replace('\\n', '\n')
    
    # Load the private key
    private_key = serialization.load_pem_private_key(
        rsa_private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    return private_key


def get_encryption_key():
    """
    Hybrid Encryption Key Derivation
    
    Step 1: Load RSA private key from environment
    Step 2: Load encrypted AES key from environment
    Step 3: Decrypt AES key using RSA private key
    Step 4: Return plaintext AES key (in memory only)
    
    This ensures:
    - AES key is NEVER stored in plaintext
    - Removing RSA private key breaks decryption
    - Same level of security as HTTPS
    """
    try:
        print(f"\n{'='*80}")
        print("🔐 HYBRID ENCRYPTION KEY DERIVATION")
        print(f"{'='*80}")
        
        # Step 1: Get RSA private key
        print("Step 1: Loading RSA-2048 Private Key...")
        rsa_private_key = get_rsa_private_key()
        
        # Get public key info
        public_key = rsa_private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"✅ RSA Private Key Loaded: {rsa_private_key.key_size} bits")
        print(f"   Public Key Preview (first 100 chars):")
        print(f"   {public_pem.decode()[:100]}...")
        
        # Step 2: Get encrypted AES key from environment
        print("\nStep 2: Loading Encrypted AES Key...")
        encrypted_aes_key_hex = os.getenv('ENCRYPTED_AES_KEY')
        
        if not encrypted_aes_key_hex:
            raise ValueError("❌ ENCRYPTED_AES_KEY not found in .env - Phase 6 setup incomplete")
        
        # Convert hex to bytes
        encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
        print(f"✅ Encrypted AES Key: {len(encrypted_aes_key)} bytes")
        print(f"   Encrypted Key (hex, first 60 chars): {encrypted_aes_key_hex[:60]}...")
        
        # Step 3: Decrypt AES key using RSA private key (OAEP with SHA-256)
        print("\nStep 3: Decrypting AES Key with RSA Private Key...")
        print("   Using: RSA-OAEP with MGF1-SHA256 padding")
        plaintext_aes_key = rsa_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"✅ AES Key Decrypted: {len(plaintext_aes_key)} bytes")
        print(f"   Plaintext AES Key (hex): {plaintext_aes_key.hex()[:60]}...")
        
        # Step 4: Return as base64 (Fernet format)
        fernet_key = base64.urlsafe_b64encode(plaintext_aes_key)
        print(f"✅ Fernet Key Generated: {len(fernet_key)} bytes (Base64 encoded)")
        print(f"{'='*80}\n")
        
        return fernet_key
        
    except Exception as e:
        print(f"❌ ERROR decrypting AES key: {str(e)}")
        raise


def encrypt_certificate(certificate_content):
    """
    Encrypt certificate content using Fernet (AES)
    Returns: encrypted bytes
    """
    try:
        print(f"\n{'='*80}")
        print("🔒 ENCRYPTING CERTIFICATE CONTENT")
        print(f"{'='*80}")
        
        # Show original content
        if isinstance(certificate_content, str):
            content_preview = certificate_content[:100] + "..." if len(certificate_content) > 100 else certificate_content
            print(f"Original Content ({len(certificate_content)} chars):")
            print(f"   {content_preview}")
            certificate_content = certificate_content.encode()
        
        print(f"\n✅ Content converted to bytes: {len(certificate_content)} bytes")
        
        # Get encryption key (triggers verbose key derivation)
        key = get_encryption_key()
        cipher = Fernet(key)
        
        print("Encrypting with AES-256 (Fernet)...")
        encrypted = cipher.encrypt(certificate_content)
        
        print(f"✅ Encryption Complete!")
        print(f"   Encrypted Size: {len(encrypted)} bytes")
        print(f"   Encrypted Content (Base64, first 80 chars):")
        print(f"   {base64.b64encode(encrypted).decode()[:80]}...")
        print(f"{'='*80}\n")
        
        return encrypted
    except Exception as e:
        print(f"❌ Encryption Error: {str(e)}")
        return None


def decrypt_certificate(encrypted_content):
    """
    Decrypt certificate content using Fernet (AES)
    Returns: decrypted string content
    """
    try:
        key = get_encryption_key()
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_content)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"❌ Decryption Error: {str(e)}")
        return None


def save_encrypted_certificate(certificate_id, encrypted_content):
    """
    Save encrypted certificate to secure_certificates directory
    Returns: file path
    """
    try:
        secure_dir = os.path.join(os.path.dirname(__file__), 'secure_certificates')
        os.makedirs(secure_dir, exist_ok=True)
        
        filename = f"cert_{certificate_id}.enc"
        filepath = os.path.join(secure_dir, filename)
        
        with open(filepath, 'wb') as f:
            f.write(encrypted_content)
        
        return filepath
    except Exception as e:
        print(f"❌ Error saving encrypted certificate: {str(e)}")
        return None


def load_encrypted_certificate(filepath):
    """
    Load encrypted certificate from file
    Returns: encrypted bytes
    """
    try:
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, 'rb') as f:
            encrypted_content = f.read()
        
        return encrypted_content
    except Exception as e:
        print(f"❌ Error loading encrypted certificate: {str(e)}")
        return None


def generate_certificate_text(applicant_name, certificate_type, approval_date):
    """
    Generate certificate text content
    Returns: certificate text as string
    """
    cert_number = secrets.token_hex(8).upper()
    
    certificate_text = f"""
═══════════════════════════════════════════════════════════════════════════════
                    SECURE CERTIFICATE AUTHORITY
                        OFFICIAL CERTIFICATE
═══════════════════════════════════════════════════════════════════════════════

Certificate Number: {cert_number}
Certificate Type: {certificate_type}

This is to certify that

    {applicant_name.upper()}

has successfully completed the verification process and is hereby granted this
{certificate_type} by the Secure Certificate Authority.

Issue Date: {approval_date.strftime('%B %d, %Y')}
Expiry Date: {(approval_date + timedelta(days=365)).strftime('%B %d, %Y')}

Status: VALID AND ACTIVE

This certificate is encrypted and tamper-proof. Only the authorized owner can
decrypt and view the complete certificate details.

═══════════════════════════════════════════════════════════════════════════════
Digitally signed by Secure Certificate Authority
Authority Key ID: {secrets.token_hex(4).upper()}
═══════════════════════════════════════════════════════════════════════════════
"""
    
    return certificate_text


# ============================================
# Digital Signature Functions (Phase 7)
# ============================================

def get_rsa_public_key():
    """
    Extract RSA public key from private key
    Returns: RSA public key object
    """
    try:
        private_key = get_rsa_private_key()
        public_key = private_key.public_key()
        return public_key
    except Exception as e:
        print(f"❌ ERROR getting RSA public key: {str(e)}")
        raise


def sign_certificate(certificate_content):
    """
    Sign certificate content using RSA-2048 private key
    
    Process:
    1. Hash certificate content with SHA-256
    2. Sign hash using RSA private key (PSS padding)
    3. Return signature bytes
    
    Returns: signature bytes (hex string for storage)
    """
    try:
        print(f"\n{'='*80}")
        print("✍️  DIGITAL SIGNATURE GENERATION")
        print(f"{'='*80}")
        
        # Get RSA private key
        print("Loading RSA-2048 Private Key for signing...")
        rsa_private_key = get_rsa_private_key()
        print(f"✅ RSA Private Key Loaded: {rsa_private_key.key_size} bits")
        
        # Convert content to bytes if needed
        if isinstance(certificate_content, str):
            certificate_content = certificate_content.encode()
        
        print(f"\nContent to Sign: {len(certificate_content)} bytes")
        
        # Calculate SHA-256 hash first (for display)
        from cryptography.hazmat.primitives import hashes as crypto_hashes
        from cryptography.hazmat.backends import default_backend
        digest = crypto_hashes.Hash(crypto_hashes.SHA256(), backend=default_backend())
        digest.update(certificate_content)
        content_hash = digest.finalize()
        print(f"✅ SHA-256 Hash: {content_hash.hex()[:60]}...")
        
        # Sign using RSA-PSS with SHA-256
        print("\nSigning with RSA-PSS (Probabilistic Signature Scheme)...")
        print("   Padding: PSS with MGF1-SHA256")
        print("   Hash Algorithm: SHA-256")
        
        signature = rsa_private_key.sign(
            certificate_content,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Convert to hex for storage
        signature_hex = signature.hex()
        
        print(f"✅ Digital Signature Created: {len(signature)} bytes")
        print(f"   Signature (hex, first 80 chars):")
        print(f"   {signature_hex[:80]}...")
        print(f"{'='*80}\n")
        
        return signature_hex
        
    except Exception as e:
        print(f"❌ ERROR signing certificate: {str(e)}")
        return None


def verify_signature(certificate_content, signature_hex):
    """
    Verify certificate signature using RSA-2048 public key
    
    Process:
    1. Get RSA public key from private key
    2. Convert signature from hex to bytes
    3. Verify signature using RSA public key (PSS padding)
    4. Return True if valid, False if invalid
    
    Returns: Boolean (True = valid, False = invalid)
    """
    try:
        if not signature_hex:
            print("⚠️  WARNING: No signature found for certificate")
            return False
        
        # Get RSA public key
        rsa_public_key = get_rsa_public_key()
        
        # Convert content to bytes if needed
        if isinstance(certificate_content, str):
            certificate_content = certificate_content.encode()
        
        # Convert signature from hex to bytes
        signature_bytes = bytes.fromhex(signature_hex)
        
        # Verify signature using RSA-PSS with SHA-256
        try:
            rsa_public_key.verify(
                signature_bytes,
                certificate_content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("✅ Signature verified successfully")
            return True
            
        except Exception as sig_error:
            print(f"⚠️  SIGNATURE VERIFICATION FAILED: {str(sig_error)}")
            return False
            
    except Exception as e:
        print(f"❌ ERROR verifying signature: {str(e)}")
        return False


# ============================================
# RBAC Decorators
# ============================================

def login_required(f):
    """Decorator to require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def otp_verified_required(f):
    """Decorator to require OTP verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        if not session.get('otp_verified'):
            return redirect(url_for('verify_otp'))
        
        # For TOTP users, session validity is managed by Flask's session cookie lifetime
        # Only check database timeout for email OTP users (who have otp_sessions entries)
        mfa_type = session.get('mfa_type')
        if mfa_type != 'totp':
            # Validate that the OTP session is still active and not expired (email OTP only)
            if not validate_session_timeout(session['user_id']):
                session.clear()
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function


def applicant_only(f):
    """RBAC Decorator: Applicant role only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        if not session.get('otp_verified'):
            return redirect(url_for('verify_otp'))
        
        if session.get('role') != 'applicant':
            user_id = session.get('user_id')
            user_role = session.get('role', 'unknown')
            user_email = session.get('email', 'unknown')
            create_audit_log(
                user_id,
                'unauthorized_access_attempt',
                resource=f.__name__,
                status='failure',
                details=f'User {user_email} with role {user_role} attempted to access applicant function {f.__name__}'
            )
            print(f"\n⚠️  UNAUTHORIZED ACCESS ATTEMPT")
            print(f"User: {user_email}")
            print(f"Role: {user_role}")
            print(f"Attempted: {f.__name__} (Applicant Only)\n")
            return render_template('403.html', 
                                 message='Applicant access only. This action is restricted to applicant users.',
                                 user_role=user_role,
                                 required_role='applicant'), 403
        
        return f(*args, **kwargs)
    return decorated_function


def verifier_only(f):
    """RBAC Decorator: Verifier role only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        if not session.get('otp_verified'):
            return redirect(url_for('verify_otp'))
        
        if session.get('role') != 'verifier':
            user_id = session.get('user_id')
            user_role = session.get('role', 'unknown')
            user_email = session.get('email', 'unknown')
            create_audit_log(
                user_id,
                'unauthorized_access_attempt',
                resource=f.__name__,
                status='failure',
                details=f'User {user_email} with role {user_role} attempted to access verifier function {f.__name__}'
            )
            print(f"\n⚠️  UNAUTHORIZED ACCESS ATTEMPT")
            print(f"User: {user_email}")
            print(f"Role: {user_role}")
            print(f"Attempted: {f.__name__} (Verifier Only)\n")
            return render_template('403.html', 
                                 message='Verifier access only. This action requires verifier privileges.',
                                 user_role=user_role,
                                 required_role='verifier'), 403
        
        return f(*args, **kwargs)
    return decorated_function


def admin_only(f):
    """RBAC Decorator: Admin role only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        if not session.get('otp_verified'):
            return redirect(url_for('verify_otp'))
        
        if session.get('role') != 'admin':
            user_id = session.get('user_id')
            user_role = session.get('role', 'unknown')
            user_email = session.get('email', 'unknown')
            create_audit_log(
                user_id,
                'unauthorized_access_attempt',
                resource=f.__name__,
                status='failure',
                details=f'User {user_email} with role {user_role} attempted to access admin function {f.__name__}'
            )
            print(f"\n⚠️  UNAUTHORIZED ACCESS ATTEMPT")
            print(f"User: {user_email}")
            print(f"Role: {user_role}")
            print(f"Attempted: {f.__name__} (Admin Only)\n")
            return render_template('403.html', 
                                 message='Admin access only. This action requires administrator privileges.',
                                 user_role=user_role,
                                 required_role='admin'), 403
        
        return f(*args, **kwargs)
    return decorated_function


def certificate_owner_only(f):
    """RBAC Decorator: Certificate owner verification"""
    @wraps(f)
    def decorated_function(cert_id, *args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        if not session.get('otp_verified'):
            return redirect(url_for('verify_otp'))
        
        # Decode certificate ID
        decoded_cert_id = decode_cert_id(cert_id)
        if decoded_cert_id is None:
            create_audit_log(
                session.get('user_id'),
                'certificate_access_invalid_encoding',
                resource='certificate',
                status='failure',
                details='Invalid certificate ID encoding'
            )
            return render_template('400.html', message='Invalid certificate ID'), 400
        
        # Check if certificate exists
        cert_request = certificate_requests_collection.find_one({'_id': decoded_cert_id})
        if not cert_request:
            return render_template('404.html', message='Certificate not found'), 404
        
        # Verify ownership (only owner can access their certificate)
        if str(cert_request['applicant_id']) != session['user_id']:
            user_email = session.get('email', 'unknown')
            create_audit_log(
                session['user_id'],
                'unauthorized_certificate_access',
                resource='certificate',
                status='failure',
                details=f'User {user_email} attempted to access certificate {decoded_cert_id} owned by another user'
            )
            print(f"\n⚠️  UNAUTHORIZED CERTIFICATE ACCESS ATTEMPT")
            print(f"User: {user_email}")
            print(f"Certificate: {decoded_cert_id}")
            print(f"Owner: Different user\n")
            return render_template('403.html', 
                                 message='You do not have permission to access this certificate. You can only view certificates that you requested.',
                                 user_role=session.get('role', 'unknown')), 403
        
        # Pass decoded cert_id to the function
        return f(decoded_cert_id, *args, **kwargs)
    return decorated_function


# ============================================
# Database Initialization
# ============================================

def initialize_mongodb():
    """Initialize MongoDB with default admin user"""
    try:
        admin_email = 'admin@certificate-authority.com'
        existing_admin = get_user_by_email(admin_email)
        
        if not existing_admin:
            admin_password = 'Admin@Secure123'
            password_hash, password_salt = hash_password(admin_password)
            
            admin_id = create_user(
                'System Administrator',
                admin_email,
                password_hash,
                password_salt,
                role='admin',
                status='active'
            )
            
            print(f"\n{'='*60}")
            print(f"🔧 MongoDB INITIALIZED WITH DEFAULT ADMIN")
            print(f"{'='*60}")
            print(f"Email: {admin_email}")
            print(f"Password: {admin_password}")
            print(f"{'='*60}\n")
        else:
            print(f"✅ MongoDB already initialized with admin user")
    
    except Exception as e:
        print(f"❌ Initialization Error: {str(e)}")


# ============================================
# Static Files Route
# ============================================

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files from ui folder"""
    return send_from_directory('ui', filename)


# ============================================
# Routes - Authentication
# ============================================

@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User Registration Route"""
    if request.method == 'POST':
        try:
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            role = request.form.get('role', 'applicant')
            
            # Validation
            if not all([full_name, email, password, confirm_password]):
                return render_template('register.html', error='All fields are required')
            
            # Security: Prevent admin registration through public form
            if role == 'admin':
                print(f"\n{'='*60}")
                print(f"🚨 SECURITY ALERT: Attempted Admin Registration")
                print(f"{'='*60}")
                print(f"Email: {email}")
                print(f"IP: {request.remote_addr}")
                print(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
                print(f"{'='*60}\n")
                
                # Log security incident (without user_id since registration blocked)
                audit_logs.insert_one({
                    'user_id': None,
                    'email': email,
                    'action': 'admin_registration_blocked',
                    'timestamp': datetime.utcnow(),
                    'status': 'blocked',
                    'ip_address': request.remote_addr,
                    'details': f'Unauthorized admin registration attempt from {email}'
                })
                
                return render_template('register.html', 
                    error='Administrator accounts cannot be created through registration. Contact system administrator.')
            
            if password != confirm_password:
                return render_template('register.html', error='Passwords do not match')
            
            # NIST SP 800-63B Password Validation
            is_valid, password_error = validate_password_nist(password, email=email, full_name=full_name)
            if not is_valid:
                return render_template('register.html', error=password_error)
            
            # Check if user exists
            existing_user = get_user_by_email(email)
            if existing_user:
                return render_template('register.html', error='Email already registered')
            
            # Create user - Verifiers require admin approval
            password_hash, password_salt = hash_password(password)
            
            # Set status based on role
            if role == 'verifier':
                user_status = 'pending_approval'
            else:
                user_status = 'active'
            
            user_id = create_user(full_name, email, password_hash, password_salt, role=role, status=user_status)
            
            if not user_id:
                return render_template('register.html', error='Registration failed. Please try again.')
            
            create_audit_log(user_id, 'user_registered', status='success', details=f'Role: {role}, Status: {user_status}')
            
            print(f"\n{'='*60}")
            if role == 'verifier':
                print(f"⏳ Verifier Registration Pending Approval!")
                print(f"{'='*60}")
                print(f"Email: {email}")
                print(f"Role: {role.upper()}")
                print(f"Status: PENDING ADMIN APPROVAL")
                print(f"Admin must approve before login is allowed.")
            else:
                print(f"✅ Registration Successful!")
                print(f"{'='*60}")
                print(f"Email: {email}")
                print(f"Role: {role.upper()}")
                print(f"Please proceed to login.")
            print(f"{'='*60}\n")
            
            # Redirect based on role
            if role == 'verifier':
                return render_template('register.html', 
                    success='Registration submitted! Your verifier account requires admin approval. You will be notified once approved.')
            else:
                return redirect(url_for('login') + '?registered=success')
        
        except Exception as e:
            print(f"❌ Registration Error: {str(e)}")
            return render_template('register.html', error='Registration failed. Please try again.')
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User Login Route"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not email or not password:
                return render_template('login.html', error='Email and password are required')
            
            # Find user
            user = get_user_by_email(email)
            
            if not user:
                print(f"⚠️  Login Attempt - User not found: {email}")
                return render_template('login.html', error='User not registered. Please create an account.')
            
            # Verify password
            if not verify_password(password, user['password_hash'], user['password_salt']):
                print(f"⚠️  Login Attempt - Invalid password for: {email}")
                create_audit_log(str(user['_id']), 'login_failed', status='failure', details='Invalid password')
                return render_template('login.html', error='Invalid password. Please try again.')
            
            if user['status'] == 'pending_approval':
                print(f"⚠️  Login Attempt - Pending approval: {email}")
                return render_template('login.html', error='Your account is pending admin approval. Please wait for approval.')
            
            if user['status'] == 'rejected':
                print(f"⚠️  Login Attempt - Account rejected: {email}")
                return render_template('login.html', error='Your account registration was rejected. Contact administrator.')
            
            if user['status'] != 'active':
                print(f"⚠️  Login Attempt - Account inactive: {email}")
                return render_template('login.html', error='Account is inactive. Contact administrator.')
            
            # Store in session - CONVERT ObjectId TO STRING
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            session['otp_verified'] = False
            session.permanent = True
            
            # Check if MFA (TOTP) is enabled for this user
            if user.get('mfa_enabled') and user.get('mfa_secret'):
                # MFA enabled - redirect to OTP page for TOTP verification
                session['mfa_type'] = 'totp'
                
                print(f"\n{'='*60}")
                print(f"🔐 TOTP MFA VERIFICATION REQUIRED")
                print(f"{'='*60}")
                print(f"Email: {email}")
                print(f"MFA Type: Authenticator App (TOTP)")
                print(f"User must enter code from their authenticator app")
                print(f"{'='*60}\n")
                
                create_audit_log(str(user['_id']), 'login_success', details='TOTP MFA required')
                return redirect(url_for('verify_otp'))
            else:
                # MFA NOT enabled - force user to set up TOTP (no email OTP fallback)
                print(f"\n{'='*60}")
                print(f"⚠️  MFA SETUP REQUIRED")
                print(f"{'='*60}")
                print(f"Email: {email}")
                print(f"User must configure authenticator app before proceeding")
                print(f"{'='*60}\n")
                
                create_audit_log(str(user['_id']), 'login_success', details='MFA setup required - redirecting to setup')
                return redirect(url_for('mfa_setup'))
        
        except Exception as e:
            print(f"❌ Login Error: {str(e)}")
            return render_template('login.html', error='Login failed. Please try again.')
    
    return render_template('login.html')


@app.route('/otp', methods=['GET', 'POST'])
def verify_otp():
    """OTP Verification Route - Handles both TOTP (authenticator app) and Email OTP"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Clean up expired sessions on every OTP page visit
    cleanup_expired_otp_sessions()
    
    # Determine MFA type
    mfa_type = session.get('mfa_type', 'email_otp')
    user = get_user_by_id(session['user_id'])
    
    if request.method == 'POST':
        try:
            otp_code = request.form.get('otp', '').strip()
            
            if not otp_code or len(otp_code) != 6:
                return render_template('otp.html', error='Code must be 6 digits', mfa_type=mfa_type), 400
            
            # Handle TOTP (Authenticator App) verification
            if mfa_type == 'totp' and user and user.get('mfa_secret'):
                if verify_totp_code(user.get('mfa_secret'), otp_code):
                    # TOTP verified successfully
                    session['otp_verified'] = True
                    session.permanent = True
                    
                    # Update user's last login
                    update_user_last_login(session['user_id'])
                    
                    create_audit_log(session['user_id'], 'totp_verified', status='success',
                                   details='Authenticator app verification successful')
                    
                    print(f"\n{'='*60}")
                    print(f"✅ TOTP Verified Successfully")
                    print(f"Email: {session['email']}")
                    print(f"Role: {session['role'].upper()}")
                    print(f"MFA Type: Authenticator App")
                    print(f"{'='*60}\n")
                    
                    return redirect(url_for('dashboard'))
                else:
                    create_audit_log(
                        session['user_id'],
                        'totp_verification_failed',
                        status='failure',
                        details='Invalid authenticator code'
                    )
                    return render_template('otp.html', error='Invalid code. Please check your authenticator app and try again.', mfa_type=mfa_type), 400
            
            # Handle Email OTP verification (original behavior)
            otp_session = get_latest_otp_session(session['user_id'])
            
            if not otp_session:
                return render_template('otp.html', error='No OTP session found. Please login again.', mfa_type=mfa_type), 400
            
            # Check if expired
            if datetime.utcnow() > otp_session['expires_at']:
                return render_template('otp.html', error='OTP has expired. Please request a new OTP.', mfa_type=mfa_type), 401
            
            # Check if max attempts exceeded
            if otp_session['attempts'] >= 5:
                session.clear()
                return render_template('otp.html', error='Too many failed attempts. Please login again.', mfa_type=mfa_type), 429
            
            # Verify OTP
            if otp_session['otp_code'] != otp_code:
                new_attempts = otp_session['attempts'] + 1
                update_otp_session(otp_session['_id'], attempts=new_attempts)
                create_audit_log(
                    session['user_id'],
                    'otp_verification_failed',
                    status='failure',
                    details=f'Attempt {new_attempts}/5'
                )
                remaining = 5 - new_attempts
                if remaining == 0:
                    session.clear()
                    return render_template('otp.html', error='Too many failed attempts. Please login again.', mfa_type=mfa_type), 429
                error_msg = f'Invalid OTP. {remaining} attempt{"s" if remaining != 1 else ""} remaining.'
                return render_template('otp.html', error=error_msg, mfa_type=mfa_type), 400
            
            # OTP verified successfully
            update_otp_session(otp_session['_id'], is_verified=True)
            session['otp_verified'] = True
            session.permanent = True
            
            # Update user's last login
            update_user_last_login(session['user_id'])
            
            create_audit_log(session['user_id'], 'otp_verified', status='success')
            
            print(f"\n{'='*60}")
            print(f"✅ OTP Verified Successfully")
            print(f"Email: {session['email']}")
            print(f"Role: {session['role'].upper()}")
            print(f"{'='*60}\n")
            
            return redirect(url_for('dashboard'))
        
        except Exception as e:
            print(f"❌ OTP Error: {str(e)}")
            import traceback
            traceback.print_exc()
            return render_template('otp.html', error='Verification failed. Please try again.', mfa_type=mfa_type), 500
    
    return render_template('otp.html', mfa_type=mfa_type)


@app.route('/otp-resend', methods=['POST'])
def resend_otp():
    """Resend OTP to user (only for email OTP, not TOTP)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    mfa_type = session.get('mfa_type', 'email_otp')
    
    # TOTP users don't need resend - codes refresh automatically every 30 seconds
    if mfa_type == 'totp':
        return render_template('otp.html', 
                             error='Authenticator app codes refresh automatically every 30 seconds. Please check your app.',
                             mfa_type=mfa_type)
    
    try:
        # Get user
        user = get_user_by_id(session['user_id'])
        if not user:
            return render_template('otp.html', error='User not found', mfa_type=mfa_type)
        
        # Generate new OTP
        otp_code = generate_otp()
        otp_expiry = datetime.utcnow() + timedelta(minutes=5)
        
        # Create new OTP session (invalidates old one implicitly with new entry)
        create_otp_session(user['_id'], otp_code, otp_expiry)
        
        print(f"\n{'='*60}")
        print(f"📱 OTP RESENT")
        print(f"{'='*60}")
        print(f"Email: {user['email']}")
        print(f"OTP Code: {otp_code}")
        print(f"Valid for: 5 minutes")
        print(f"{'='*60}\n")
        
        create_audit_log(
            session['user_id'],
            'otp_resent',
            status='success',
            details='New OTP generated and resent'
        )
        
        return render_template('otp.html', success='A new OTP has been sent to your email. Please check and enter it below.', mfa_type=mfa_type)
    
    except Exception as e:
        print(f"❌ OTP Resend Error: {str(e)}")
        return render_template('otp.html', error='Failed to resend OTP. Please try again.', mfa_type=mfa_type)


@app.route('/logout')
def logout():
    """User Logout"""
    user_id = session.get('user_id')
    if user_id:
        create_audit_log(user_id, 'logout', status='success')
    
    session.clear()
    return redirect(url_for('index'))


# ============================================
# MFA Setup & Verification Routes (TOTP Authenticator App)
# ============================================

@app.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    """
    MFA Setup - Generate TOTP secret and QR code
    User scans QR code with authenticator app (Google Authenticator, Authy, etc.)
    """
    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        # Generate new TOTP secret
        mfa_secret = generate_totp_secret()
        
        # Store secret (not yet enabled)
        update_user_mfa_secret(session['user_id'], mfa_secret)
        
        # Generate provisioning URI for QR code
        provisioning_uri = get_totp_provisioning_uri(mfa_secret, user['email'])
        
        # Generate QR code image
        qr_code_base64 = generate_totp_qr_code(provisioning_uri)
        
        print(f"\n{'='*60}")
        print(f"🔐 MFA SETUP INITIATED")
        print(f"{'='*60}")
        print(f"Email: {user['email']}")
        print(f"Secret: {mfa_secret}")
        print(f"URI: {provisioning_uri}")
        print(f"{'='*60}\n")
        
        create_audit_log(session['user_id'], 'mfa_setup_initiated', status='success')
        
        return render_template('mfa_setup.html', 
                             qr_code=qr_code_base64, 
                             secret=mfa_secret,
                             email=user['email'])
    
    return redirect(url_for('dashboard'))


@app.route('/mfa/verify', methods=['POST'])
@login_required
def mfa_verify():
    """
    MFA Verify - Verify TOTP code and enable MFA
    Called after user scans QR code and enters code from authenticator app
    Uses @login_required (not @otp_verified_required) because user is setting up MFA for first time
    """
    user = get_user_by_id(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    code = request.form.get('code', '').strip()
    
    if not code or len(code) != 6:
        return jsonify({'success': False, 'error': 'Please enter a 6-digit code'}), 400
    
    mfa_secret = user.get('mfa_secret')
    if not mfa_secret:
        return jsonify({'success': False, 'error': 'MFA not set up. Please scan QR code first.'}), 400
    
    # Verify the TOTP code
    if verify_totp_code(mfa_secret, code):
        # Enable MFA for user
        enable_user_mfa(session['user_id'])
        
        # Mark user as fully verified (OTP verified) so they can access dashboard
        session['otp_verified'] = True
        session.permanent = True
        
        # Update last login timestamp
        update_user_last_login(session['user_id'])
        
        print(f"\n{'='*60}")
        print(f"✅ MFA ENABLED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"Email: {user['email']}")
        print(f"MFA Type: TOTP (Authenticator App)")
        print(f"User is now fully authenticated")
        print(f"{'='*60}\n")
        
        create_audit_log(session['user_id'], 'mfa_enabled', status='success', 
                        details='TOTP authenticator app configured - user fully authenticated')
        
        return jsonify({
            'success': True, 
            'message': 'MFA enabled successfully! Redirecting to dashboard...'
        })
    else:
        create_audit_log(session['user_id'], 'mfa_verify_failed', status='failure',
                        details='Invalid TOTP code during setup')
        return jsonify({'success': False, 'error': 'Invalid code. Please try again.'}), 400


@app.route('/mfa/disable', methods=['POST'])
@otp_verified_required
def mfa_disable():
    """
    MFA Disable - Disable TOTP MFA for user
    Requires current TOTP code to disable
    """
    user = get_user_by_id(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    if not user.get('mfa_enabled'):
        return jsonify({'success': False, 'error': 'MFA is not enabled'}), 400
    
    code = request.form.get('code', '').strip()
    
    if not code or len(code) != 6:
        return jsonify({'success': False, 'error': 'Please enter your authenticator code'}), 400
    
    # Verify the TOTP code before disabling
    if verify_totp_code(user.get('mfa_secret'), code):
        disable_user_mfa(session['user_id'])
        
        print(f"\n{'='*60}")
        print(f"⚠️  MFA DISABLED")
        print(f"{'='*60}")
        print(f"Email: {user['email']}")
        print(f"{'='*60}\n")
        
        create_audit_log(session['user_id'], 'mfa_disabled', status='success')
        
        return jsonify({
            'success': True, 
            'message': 'MFA has been disabled. You will now use email OTP for login.'
        })
    else:
        create_audit_log(session['user_id'], 'mfa_disable_failed', status='failure',
                        details='Invalid TOTP code when trying to disable')
        return jsonify({'success': False, 'error': 'Invalid code. Please try again.'}), 400


@app.route('/mfa/status')
@otp_verified_required
def mfa_status():
    """Get current MFA status for user"""
    user = get_user_by_id(session['user_id'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    return jsonify({
        'success': True,
        'mfa_enabled': user.get('mfa_enabled', False),
        'mfa_type': 'totp' if user.get('mfa_enabled') else 'email_otp'
    })


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot Password - Request OTP"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            
            if not email:
                return render_template('forgot_password.html', error='Email is required')
            
            # Find user
            user = get_user_by_email(email)
            
            # Security: Don't reveal if email exists or not
            if user:
                # Generate OTP for password reset
                otp_code = generate_otp()
                otp_expiry = datetime.utcnow() + timedelta(minutes=10)
                
                # Store OTP in reset_password_otps collection
                db['reset_password_otps'].insert_one({
                    'user_id': user['_id'],
                    'email': user['email'],
                    'otp_code': otp_code,
                    'expires_at': otp_expiry,
                    'attempts': 0,
                    'is_used': False,
                    'created_at': datetime.utcnow()
                })
                
                print(f"\n{'='*60}")
                print(f"🔐 PASSWORD RESET OTP")
                print(f"{'='*60}")
                print(f"Email: {email}")
                print(f"OTP Code: {otp_code}")
                print(f"Valid for: 10 minutes")
                print(f"{'='*60}\n")
                
                create_audit_log(
                    str(user['_id']),
                    'password_reset_requested',
                    status='success',
                    details='Password reset OTP generated'
                )
            
            # Always show success message (security best practice)
            return render_template('forgot_password.html', 
                success='If the email exists, an OTP has been sent. Please check and proceed to reset password.')
        
        except Exception as e:
            print(f"❌ Forgot Password Error: {str(e)}")
            return render_template('forgot_password.html', error='An error occurred. Please try again.')
    
    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Reset Password with OTP"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            otp_code = request.form.get('otp', '').strip()
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Validation
            if not all([email, otp_code, new_password, confirm_password]):
                return render_template('reset_password.html', error='All fields are required')
            
            if new_password != confirm_password:
                return render_template('reset_password.html', error='Passwords do not match')
            
            # NIST SP 800-63B Password Validation
            user_for_validation = get_user_by_email(email)
            full_name = user_for_validation.get('full_name', '') if user_for_validation else ''
            is_valid, password_error = validate_password_nist(new_password, email=email, full_name=full_name)
            if not is_valid:
                return render_template('reset_password.html', error=password_error)
            
            # Find user
            user = get_user_by_email(email)
            if not user:
                return render_template('reset_password.html', error='Invalid email or OTP')
            
            # Get latest reset OTP for this user
            reset_otp = db['reset_password_otps'].find_one({
                'user_id': user['_id'],
                'is_used': False
            }, sort=[('created_at', -1)])
            
            if not reset_otp:
                return render_template('reset_password.html', error='No valid OTP found. Please request a new one.')
            
            # Check if expired
            if datetime.utcnow() > reset_otp['expires_at']:
                return render_template('reset_password.html', error='OTP has expired. Please request a new one.')
            
            # Check attempts
            if reset_otp['attempts'] >= 5:
                return render_template('reset_password.html', error='Too many failed attempts. Please request a new OTP.')
            
            # Verify OTP
            if reset_otp['otp_code'] != otp_code:
                # Increment attempts
                db['reset_password_otps'].update_one(
                    {'_id': reset_otp['_id']},
                    {'$inc': {'attempts': 1}}
                )
                remaining = 5 - (reset_otp['attempts'] + 1)
                error_msg = f'Invalid OTP. {remaining} attempt{"s" if remaining != 1 else ""} remaining.'
                return render_template('reset_password.html', error=error_msg)
            
            # OTP is valid - update password
            new_password_hash, new_password_salt = hash_password(new_password)
            
            users_collection.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'password_hash': new_password_hash,
                        'password_salt': new_password_salt
                    }
                }
            )
            
            # Mark OTP as used
            db['reset_password_otps'].update_one(
                {'_id': reset_otp['_id']},
                {'$set': {'is_used': True}}
            )
            
            create_audit_log(
                str(user['_id']),
                'password_reset_success',
                status='success',
                details='Password successfully reset'
            )
            
            print(f"\n{'='*60}")
            print(f"✅ Password Reset Successfully")
            print(f"Email: {email}")
            print(f"{'='*60}\n")
            
            return render_template('reset_password.html', 
                success='Password reset successfully! You can now login with your new password.',
                redirect_to_login=True)
        
        except Exception as e:
            print(f"❌ Reset Password Error: {str(e)}")
            import traceback
            traceback.print_exc()
            return render_template('reset_password.html', error='Password reset failed. Please try again.')
    
    return render_template('reset_password.html')


# ============================================
# Routes - Dashboard & Protected Pages
# ============================================

@app.route('/dashboard')
@otp_verified_required
def dashboard():
    """User Dashboard - Role-based content"""
    try:
        user = get_user_by_id(session['user_id'])
        if not user:
            return redirect(url_for('login'))
        
        # Prepare context based on role
        context = {
            'user': {
                'id': str(user['_id']),
                'full_name': user['full_name'],
                'email': user['email'],
                'role': user['role']
            },
            'session_data': session
        }
        
        # Add role-specific data
        if user['role'] == 'applicant':
            certificates = get_user_certificate_requests(user['_id'])
            context['certificates'] = certificates
            context['certificate_count'] = len(certificates)
            
            # Calculate status-specific counts for applicant
            context['pending_requests'] = sum(1 for cert in certificates if cert.get('status') == 'pending')
            context['verified_requests'] = sum(1 for cert in certificates if cert.get('status') == 'verified')
            context['approved_certificates'] = sum(1 for cert in certificates if cert.get('status') == 'approved')
        
        elif user['role'] == 'verifier':
            pending = get_pending_certificate_requests()
            context['pending_count'] = len(pending)
            context['verified_count'] = certificate_requests_collection.count_documents({'status': 'verified'})
            context['rejected_count'] = certificate_requests_collection.count_documents({'status': 'rejected'})
        
        elif user['role'] == 'admin':
            verified = get_verified_certificate_requests()
            context['verified_count'] = len(verified)
            context['approved_count'] = certificate_requests_collection.count_documents({'status': 'approved'})
            context['admin_rejected_count'] = certificate_requests_collection.count_documents({'status': 'admin_rejected'})
            context['total_audit_logs'] = audit_logs_collection.count_documents({})
        
        create_audit_log(session['user_id'], 'dashboard_accessed', status='success')
        
        return render_template('dashboard.html', **context)
    
    except Exception as e:
        print(f"❌ Dashboard Error: {str(e)}")
        return redirect(url_for('login'))


# ============================================
# Routes - Applicant Only
# ============================================

@app.route('/request-certificate', methods=['GET', 'POST'])
@applicant_only
def request_certificate():
    """Request a new certificate"""
    if request.method == 'POST':
        try:
            certificate_type = request.form.get('certificate_type', '').strip()
            purpose = request.form.get('purpose', '').strip()
            
            if not certificate_type or not purpose:
                return render_template('request_certificate.html', error='All fields are required'), 400
            
            # Create the certificate request
            cert_id = create_certificate_request(session['user_id'], certificate_type, purpose)
            
            if cert_id:
                # Log the action
                create_audit_log(
                    session['user_id'],
                    'certificate_requested',
                    resource='certificate_request',
                    status='success',
                    details=f'Type: {certificate_type}'
                )
                print(f"\n{'='*60}")
                print(f"✅ CERTIFICATE REQUEST SUBMITTED")
                print(f"{'='*60}")
                print(f"Request ID: {cert_id}")
                print(f"Type: {certificate_type}")
                print(f"Purpose: {purpose[:50]}...")
                print(f"Status: PENDING (Awaiting Verification)")
                print(f"{'='*60}\n")
                
                # Return success response for AJAX
                return jsonify({'success': True, 'message': 'Certificate request submitted successfully', 'cert_id': str(cert_id)}), 200
            else:
                return jsonify({'success': False, 'error': 'Failed to submit request'}), 500
        
        except Exception as e:
            print(f"❌ Certificate Request Error: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    return render_template('request_certificate.html')


@app.route('/my-certificates')
@applicant_only
def my_certificates():
    """View user's certificate requests"""
    try:
        certificates = get_user_certificate_requests(session['user_id'])
        create_audit_log(session['user_id'], 'viewed_certificates', status='success')
        return render_template('my_certificates.html', certificates=certificates, session_data=session)
    except Exception as e:
        print(f"❌ My Certificates Error: {str(e)}")
        return render_template('my_certificates.html', certificates=[], error='Failed to load certificates')


@app.route('/certificate-types')
@otp_verified_required
def certificate_types():
    """View available certificate types (All authenticated users)"""
    certificate_types_data = [
        {'id': 1, 'name': 'SSL Certificate', 'description': 'For HTTPS website security'},
        {'id': 2, 'name': 'Code Signing Certificate', 'description': 'For software code signing'},
        {'id': 3, 'name': 'Organization Certificate', 'description': 'For organizational verification'},
        {'id': 4, 'name': 'Personal Certificate', 'description': 'For personal digital identity'}
    ]
    create_audit_log(session['user_id'], 'viewed_certificate_types', status='success')
    return render_template('certificate_types.html', types=certificate_types_data, session_data=session)


# ============================================
# Routes - Verifier Only
# ============================================

@app.route('/verifier-tasks')
@verifier_only
def verifier_tasks():
    """Verifier's task dashboard"""
    try:
        pending_requests = get_pending_certificate_requests()
        
        # Calculate statistics
        pending_count = certificate_requests_collection.count_documents({'status': 'pending'})
        verified_count = certificate_requests_collection.count_documents({'status': 'verified'})
        rejected_count = certificate_requests_collection.count_documents({'status': 'rejected'})
        total_processed = verified_count + rejected_count
        
        create_audit_log(session['user_id'], 'viewed_verifier_tasks', status='success')
        return render_template('verifier_tasks.html', 
                             requests=pending_requests, 
                             session_data=session,
                             pending_count=pending_count,
                             verified_count=verified_count,
                             rejected_count=rejected_count,
                             total_processed=total_processed)
    except Exception as e:
        print(f"❌ Verifier Tasks Error: {str(e)}")
        return render_template('verifier_tasks.html', requests=[], error='Failed to load tasks',
                             pending_count=0, verified_count=0, rejected_count=0, total_processed=0)


# ============================================
# Routes - Admin Only
# ============================================

@app.route('/admin-approvals')
@admin_only
def admin_approvals():
    """Admin approval dashboard"""
    try:
        verified_requests = get_verified_certificate_requests()
        
        # Calculate real statistics from database
        awaiting_approval = certificate_requests_collection.count_documents({'status': 'verified'})
        approved_count = certificate_requests_collection.count_documents({'status': 'approved'})
        rejected_admin_count = certificate_requests_collection.count_documents({'status': 'admin_rejected'})
        total_processed = approved_count + rejected_admin_count
        
        create_audit_log(session['user_id'], 'viewed_admin_approvals', status='success')
        return render_template('admin_approvals.html', 
                             requests=verified_requests, 
                             session_data=session,
                             awaiting_approval=awaiting_approval,
                             approved_count=approved_count,
                             rejected_count=rejected_admin_count,
                             total_processed=total_processed)
    except Exception as e:
        print(f"❌ Admin Approvals Error: {str(e)}")
        return render_template('admin_approvals.html', 
                             requests=[], 
                             error='Failed to load requests',
                             awaiting_approval=0,
                             approved_count=0,
                             rejected_count=0,
                             total_processed=0)


# ============================================
# Routes - User Management (Admin Only)
# ============================================

@app.route('/admin/user-management')
@admin_only
def user_management():
    """Admin user management dashboard - view all users, pending verifiers"""
    try:
        # Get all users except current admin
        all_users = list(users_collection.find({'_id': {'$ne': ObjectId(session['user_id'])}}).sort('created_at', -1))
        
        # Calculate statistics
        pending_verifiers = users_collection.count_documents({'role': 'verifier', 'status': 'pending_approval'})
        active_verifiers = users_collection.count_documents({'role': 'verifier', 'status': 'active'})
        active_applicants = users_collection.count_documents({'role': 'applicant', 'status': 'active'})
        total_users = users_collection.count_documents({})
        
        create_audit_log(session['user_id'], 'viewed_user_management', status='success')
        
        return render_template('user_management.html',
                             users=all_users,
                             pending_verifiers=pending_verifiers,
                             active_verifiers=active_verifiers,
                             active_applicants=active_applicants,
                             total_users=total_users,
                             session_data=session)
    except Exception as e:
        print(f"❌ User Management Error: {str(e)}")
        return render_template('user_management.html',
                             users=[],
                             error='Failed to load users',
                             pending_verifiers=0,
                             active_verifiers=0,
                             active_applicants=0,
                             total_users=0,
                             session_data=session)


@app.route('/admin/approve-verifier/<user_id>', methods=['POST'])
@admin_only
def approve_verifier(user_id):
    """Approve a pending verifier registration"""
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user['status'] != 'pending_approval':
            return jsonify({'error': 'User is not pending approval'}), 400
        
        if user['role'] != 'verifier':
            return jsonify({'error': 'User is not a verifier'}), 400
        
        # Approve the verifier
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'status': 'active',
                'approved_at': datetime.utcnow(),
                'approved_by': ObjectId(session['user_id'])
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'verifier_approved',
            resource='user',
            status='success',
            details=f'Verifier {user["email"]} approved'
        )
        
        print(f"\n{'='*60}")
        print(f"✅ VERIFIER APPROVED")
        print(f"{'='*60}")
        print(f"Email: {user['email']}")
        print(f"Approved By: {session['email']}")
        print(f"{'='*60}\n")
        
        return jsonify({'success': True, 'message': f'Verifier {user["email"]} approved successfully'}), 200
    
    except Exception as e:
        print(f"❌ Approve Verifier Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/admin/reject-verifier/<user_id>', methods=['POST'])
@admin_only
def reject_verifier(user_id):
    """Reject a pending verifier registration"""
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user['status'] != 'pending_approval':
            return jsonify({'error': 'User is not pending approval'}), 400
        
        # Get rejection reason
        rejection_reason = request.json.get('reason', 'No reason provided') if request.is_json else 'No reason provided'
        
        # Reject the verifier
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'status': 'rejected',
                'rejected_at': datetime.utcnow(),
                'rejected_by': ObjectId(session['user_id']),
                'rejection_reason': rejection_reason
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'verifier_rejected',
            resource='user',
            status='success',
            details=f'Verifier {user["email"]} rejected. Reason: {rejection_reason}'
        )
        
        print(f"\n{'='*60}")
        print(f"❌ VERIFIER REJECTED")
        print(f"{'='*60}")
        print(f"Email: {user['email']}")
        print(f"Rejected By: {session['email']}")
        print(f"Reason: {rejection_reason}")
        print(f"{'='*60}\n")
        
        return jsonify({'success': True, 'message': f'Verifier {user["email"]} rejected'}), 200
    
    except Exception as e:
        print(f"❌ Reject Verifier Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/admin/create-user', methods=['POST'])
@admin_only
def admin_create_user():
    """Admin creates a new user (verifier or applicant)"""
    try:
        data = request.json if request.is_json else request.form
        
        full_name = data.get('full_name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'applicant')
        
        # Validation
        if not all([full_name, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Admin can only create verifier or applicant
        if role not in ['verifier', 'applicant']:
            return jsonify({'error': 'Invalid role. Only verifier or applicant allowed.'}), 400
        
        # Check if user exists
        if get_user_by_email(email):
            return jsonify({'error': 'Email already registered'}), 400
        
        # Validate password
        is_valid, password_error = validate_password_nist(password, email=email, full_name=full_name)
        if not is_valid:
            return jsonify({'error': password_error}), 400
        
        # Create user (admin-created users are directly active)
        password_hash, password_salt = hash_password(password)
        user_id = create_user(full_name, email, password_hash, password_salt, role=role, status='active')
        
        if not user_id:
            return jsonify({'error': 'Failed to create user'}), 500
        
        # Record who created the user
        users_collection.update_one(
            {'_id': user_id},
            {'$set': {
                'created_by_admin': ObjectId(session['user_id']),
                'admin_created': True
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'user_created_by_admin',
            resource='user',
            status='success',
            details=f'User {email} ({role}) created by admin'
        )
        
        print(f"\n{'='*60}")
        print(f"✅ USER CREATED BY ADMIN")
        print(f"{'='*60}")
        print(f"Email: {email}")
        print(f"Role: {role.upper()}")
        print(f"Created By: {session['email']}")
        print(f"{'='*60}\n")
        
        return jsonify({'success': True, 'message': f'{role.capitalize()} {email} created successfully'}), 200
    
    except Exception as e:
        print(f"❌ Admin Create User Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/admin/edit-user/<user_id>', methods=['POST'])
@admin_only
def admin_edit_user(user_id):
    """Admin edits a user's details"""
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Prevent editing admin accounts
        if user['role'] == 'admin':
            return jsonify({'error': 'Cannot edit admin accounts'}), 403
        
        data = request.json if request.is_json else request.form
        
        update_fields = {}
        
        # Update full name if provided
        if data.get('full_name'):
            update_fields['full_name'] = data['full_name'].strip()
        
        # Update role if provided (only verifier/applicant)
        if data.get('role') and data['role'] in ['verifier', 'applicant']:
            update_fields['role'] = data['role']
        
        # Update status if provided
        if data.get('status') and data['status'] in ['active', 'inactive', 'pending_approval']:
            update_fields['status'] = data['status']
        
        # Update password if provided
        if data.get('password'):
            is_valid, password_error = validate_password_nist(data['password'], email=user['email'], full_name=user['full_name'])
            if not is_valid:
                return jsonify({'error': password_error}), 400
            password_hash, password_salt = hash_password(data['password'])
            update_fields['password_hash'] = password_hash
            update_fields['password_salt'] = password_salt
        
        if not update_fields:
            return jsonify({'error': 'No valid fields to update'}), 400
        
        update_fields['updated_at'] = datetime.utcnow()
        update_fields['updated_by'] = ObjectId(session['user_id'])
        
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_fields}
        )
        
        create_audit_log(
            session['user_id'],
            'user_edited_by_admin',
            resource='user',
            status='success',
            details=f'User {user["email"]} edited. Fields: {list(update_fields.keys())}'
        )
        
        print(f"✅ User {user['email']} updated by admin {session['email']}")
        
        return jsonify({'success': True, 'message': f'User {user["email"]} updated successfully'}), 200
    
    except Exception as e:
        print(f"❌ Admin Edit User Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/admin/delete-user/<user_id>', methods=['POST'])
@admin_only
def admin_delete_user(user_id):
    """Admin deletes a user (soft delete by setting status to deleted)"""
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Prevent deleting admin accounts
        if user['role'] == 'admin':
            return jsonify({'error': 'Cannot delete admin accounts'}), 403
        
        # Soft delete - set status to deleted
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'status': 'deleted',
                'deleted_at': datetime.utcnow(),
                'deleted_by': ObjectId(session['user_id'])
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'user_deleted_by_admin',
            resource='user',
            status='success',
            details=f'User {user["email"]} ({user["role"]}) deleted by admin'
        )
        
        print(f"🗑️ User {user['email']} deleted by admin {session['email']}")
        
        return jsonify({'success': True, 'message': f'User {user["email"]} deleted'}), 200
    
    except Exception as e:
        print(f"❌ Admin Delete User Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/audit-logs')
@admin_only
def audit_logs():
    """View system audit logs with filtering and detailed information"""
    try:
        # Get filter parameters
        action_filter = request.args.get('action', '')
        user_filter = request.args.get('user', '')
        limit = int(request.args.get('limit', 100))
        
        # Build query
        query = {}
        if action_filter:
            query['action'] = action_filter
        
        # Get logs
        logs = list(audit_logs_collection.find(query).sort('created_at', -1).limit(limit))
        
        # Enhance logs with user information
        enhanced_logs = []
        for log in logs:
            enhanced_log = {
                '_id': str(log['_id']),
                'user_id': str(log['user_id']) if log.get('user_id') else 'System',
                'action': log.get('action', 'unknown'),
                'resource': log.get('resource'),
                'status': log.get('status', 'unknown'),
                'ip_address': log.get('ip_address', 'Unknown'),
                'details': log.get('details'),
                'created_at': log.get('created_at'),
                'timestamp': log.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if log.get('created_at') else 'N/A'
            }
            
            # Try to get user email for better readability
            if log.get('user_id'):
                try:
                    user = users_collection.find_one({'_id': log['user_id']})
                    if user:
                        enhanced_log['user_email'] = user.get('email', 'Unknown')
                        enhanced_log['user_name'] = user.get('full_name', 'Unknown')
                except:
                    pass
            
            enhanced_logs.append(enhanced_log)
        
        # Get action statistics for display
        action_stats = get_action_statistics()
        
        create_audit_log(session['user_id'], 'viewed_audit_logs', 
                        resource='audit_logs', status='success', 
                        details=f'Viewed {len(logs)} logs with filters: action={action_filter}, limit={limit}')
        
        return render_template('audit_logs.html', 
                             logs=enhanced_logs, 
                             action_stats=action_stats,
                             session_data=session,
                             current_filters={'action': action_filter, 'user': user_filter})
    except Exception as e:
        print(f"❌ Audit Logs Error: {str(e)}")
        create_audit_log(session['user_id'], 'viewed_audit_logs', 
                        resource='audit_logs', status='failure', 
                        details=f'Error: {str(e)}')
        return render_template('audit_logs.html', logs=[], error='Failed to load logs', session_data=session)


# ============================================
# Routes - Certificate Management (Verifier & Admin)
# ============================================

@app.route('/verify-certificate/<cert_id>', methods=['POST'])
@verifier_only
def verify_certificate(cert_id):
    """Verify certificate request (Verifier action)"""
    try:
        # Decode certificate ID from Base64 (Phase 9)
        cert_id = decode_cert_id(cert_id)
        if cert_id is None:
            return jsonify({'error': 'Invalid certificate ID encoding'}), 400
        
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return jsonify({'error': 'Certificate not found'}), 404
        
        if cert_request['status'] != 'pending':
            return jsonify({'error': 'Certificate already processed'}), 400
        
        # Update certificate status
        certificate_requests_collection.update_one(
            {'_id': cert_id},
            {'$set': {
                'status': 'verified',
                'verified_at': datetime.utcnow(),
                'verifier_id': ObjectId(session['user_id'])
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'certificate_verified',
            resource='certificate_request',
            status='success',
            details=f'Certificate {cert_id} verified'
        )
        
        print(f"✅ Certificate {cert_id} verified by {session['email']}")
        
        return jsonify({'success': True, 'message': 'Certificate verified successfully'}), 200
    
    except Exception as e:
        print(f"❌ Certificate Verification Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/reject-certificate-verifier/<cert_id>', methods=['POST'])
@verifier_only
def reject_certificate_verifier(cert_id):
    """Reject certificate request (Verifier action)"""
    try:
        # Decode certificate ID from Base64 (Phase 9)
        cert_id = decode_cert_id(cert_id)
        if cert_id is None:
            return jsonify({'error': 'Invalid certificate ID encoding'}), 400
        
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return jsonify({'error': 'Certificate not found'}), 404
        
        if cert_request['status'] != 'pending':
            return jsonify({'error': 'Certificate already processed'}), 400
        
        # Get rejection reason from request
        rejection_reason = request.json.get('reason', 'No reason provided') if request.is_json else 'No reason provided'
        
        # Update certificate status to rejected
        certificate_requests_collection.update_one(
            {'_id': cert_id},
            {'$set': {
                'status': 'rejected',
                'rejected_at': datetime.utcnow(),
                'verifier_id': ObjectId(session['user_id']),
                'rejection_reason': rejection_reason
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'certificate_rejected_by_verifier',
            resource='certificate_request',
            status='success',
            details=f'Certificate {cert_id} rejected by verifier. Reason: {rejection_reason}'
        )
        
        print(f"❌ Certificate {cert_id} rejected by verifier {session['email']}. Reason: {rejection_reason}")
        
        return jsonify({'success': True, 'message': 'Certificate rejected successfully'}), 200
    
    except Exception as e:
        print(f"❌ Certificate Rejection Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/reject-certificate-admin/<cert_id>', methods=['POST'])
@admin_only
def reject_certificate_admin(cert_id):
    """Reject certificate request (Admin action)"""
    try:
        # Decode certificate ID from Base64 (Phase 9)
        cert_id = decode_cert_id(cert_id)
        if cert_id is None:
            return jsonify({'error': 'Invalid certificate ID encoding'}), 400
        
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return jsonify({'error': 'Certificate not found'}), 404
        
        if cert_request['status'] != 'verified':
            return jsonify({'error': 'Only verified certificates can be rejected by admin'}), 400
        
        # Get rejection reason from request
        rejection_reason = request.json.get('reason', 'No reason provided') if request.is_json else 'No reason provided'
        
        # Update certificate status to admin_rejected
        certificate_requests_collection.update_one(
            {'_id': cert_id},
            {'$set': {
                'status': 'admin_rejected',
                'admin_rejected_at': datetime.utcnow(),
                'admin_id': ObjectId(session['user_id']),
                'rejection_reason': rejection_reason
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'certificate_rejected_by_admin',
            resource='certificate_request',
            status='success',
            details=f'Certificate {cert_id} rejected by admin. Reason: {rejection_reason}'
        )
        
        print(f"❌ Certificate {cert_id} rejected by admin {session['email']}. Reason: {rejection_reason}")
        
        return jsonify({'success': True, 'message': 'Certificate rejected successfully'}), 200
    
    except Exception as e:
        print(f"❌ Admin Certificate Rejection Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/get-certificate-for-encryption/<cert_id>', methods=['GET'])
@admin_only
def get_certificate_for_encryption(cert_id):
    """Get certificate content for client-side encryption (Admin action)"""
    try:
        # Decode certificate ID from Base64 (Phase 9)
        cert_id = decode_cert_id(cert_id)
        if cert_id is None:
            return jsonify({'error': 'Invalid certificate ID encoding'}), 400
        
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return jsonify({'error': 'Certificate not found'}), 404
        
        if cert_request['status'] != 'verified':
            return jsonify({'error': 'Certificate must be verified first'}), 400
        
        # Get applicant info
        applicant = get_user_by_id(cert_request['applicant_id'])
        if not applicant:
            return jsonify({'error': 'Applicant not found'}), 404
        
        # Generate certificate content (plaintext for client-side encryption)
        cert_text = generate_certificate_text(
            applicant['full_name'],
            cert_request['certificate_type'],
            datetime.utcnow()
        )
        
        # Sign certificate (Phase 7) - signing still done server-side
        signature_hex = sign_certificate(cert_text)
        if not signature_hex:
            return jsonify({'error': 'Failed to sign certificate'}), 500
        
        print(f"\n{'='*60}")
        print(f"📄 CERTIFICATE CONTENT GENERATED FOR CLIENT-SIDE ENCRYPTION")
        print(f"{'='*60}")
        print(f"Certificate ID: {cert_id}")
        print(f"Applicant: {applicant['email']}")
        print(f"Type: {cert_request['certificate_type']}")
        print(f"Content Length: {len(cert_text)} characters")
        print(f"Signature Generated: Yes")
        print(f"{'='*60}\n")
        
        return jsonify({
            'success': True,
            'certificate_content': cert_text,
            'signature': signature_hex,
            'cert_id': str(cert_id)
        }), 200
    
    except Exception as e:
        print(f"❌ Get Certificate for Encryption Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/approve-certificate/<cert_id>', methods=['POST'])
@admin_only
def approve_certificate(cert_id):
    """Approve certificate request and store client-side encrypted certificate (Admin action)"""
    try:
        # Decode certificate ID from Base64 (Phase 9)
        cert_id = decode_cert_id(cert_id)
        if cert_id is None:
            return jsonify({'error': 'Invalid certificate ID encoding'}), 400
        
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return jsonify({'error': 'Certificate not found'}), 404
        
        if cert_request['status'] != 'verified':
            return jsonify({'error': 'Certificate must be verified first'}), 400
        
        # Get applicant info
        applicant = get_user_by_id(cert_request['applicant_id'])
        if not applicant:
            return jsonify({'error': 'Applicant not found'}), 404
        
        # Get client-side encrypted data from request
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No encryption data provided'}), 400
        
        encrypted_content = data.get('encrypted_content')
        encryption_iv = data.get('encryption_iv')
        encryption_key = data.get('encryption_key')
        signature_hex = data.get('signature')
        
        if not all([encrypted_content, encryption_iv, encryption_key, signature_hex]):
            return jsonify({'error': 'Missing encryption parameters (encrypted_content, encryption_iv, encryption_key, signature)'}), 400
        
        # Store the client-side encrypted content
        # Combine IV + encrypted content for storage
        encrypted_data = f"{encryption_iv}:{encryption_key}:{encrypted_content}"
        encrypted_bytes = encrypted_data.encode('utf-8')
        
        # Save encrypted certificate to disk
        encrypted_filepath = save_encrypted_certificate(str(cert_id), encrypted_bytes)
        if not encrypted_filepath:
            return jsonify({'error': 'Failed to save encrypted certificate'}), 500
        
        # Update certificate in database
        # Phase 10: Set expiry_date to 1 year from approval
        expiry_date = datetime.utcnow() + timedelta(days=365)
        
        certificate_requests_collection.update_one(
            {'_id': cert_id},
            {'$set': {
                'status': 'approved',
                'approved_at': datetime.utcnow(),
                'admin_id': ObjectId(session['user_id']),
                'encrypted_file_path': encrypted_filepath,
                'certificate_content': encrypted_data,  # Store client-side encrypted content
                'certificate_signature': signature_hex,  # Store signature (Phase 7)
                'encryption_type': 'client-side-aes-gcm',  # Mark as client-side encrypted
                'expiry_date': expiry_date,  # Phase 10: Certificate expires 1 year from approval
                'is_revoked': False
            }}
        )
        
        create_audit_log(
            session['user_id'],
            'certificate_approved_and_issued',
            resource='certificate_request',
            status='success',
            details=f'Certificate {cert_id} approved with CLIENT-SIDE encryption'
        )
        
        print(f"\n{'='*60}")
        print(f"🎓 CERTIFICATE ISSUED WITH CLIENT-SIDE ENCRYPTION")
        print(f"{'='*60}")
        print(f"Certificate ID: {cert_id}")
        print(f"Applicant: {applicant['email']}")
        print(f"Type: {cert_request['certificate_type']}")
        print(f"Status: APPROVED AND ENCRYPTED (CLIENT-SIDE)")
        print(f"Encrypted File: {encrypted_filepath}")
        print(f"Encryption Type: AES-256-GCM (Web Crypto API)")
        print(f"{'='*60}\n")
        
        return jsonify({
            'success': True,
            'message': 'Certificate approved with client-side encryption successfully',
            'cert_id': str(cert_id)
        }), 200
    
    except Exception as e:
        print(f"❌ Certificate Approval Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/revoke-certificate/<cert_id>', methods=['POST'])
@admin_only
def revoke_certificate_endpoint(cert_id):
    """Revoke a certificate (Admin-only action, Phase 10)"""
    try:
        # Decode certificate ID from Base64 (Phase 9)
        cert_id = decode_cert_id(cert_id)
        if cert_id is None:
            return jsonify({'error': 'Invalid certificate ID encoding'}), 400
        
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return jsonify({'error': 'Certificate not found'}), 404
        
        # Get revocation reason from request (optional)
        revocation_reason = request.json.get('reason', 'No reason provided') if request.is_json else 'No reason provided'
        
        # Check if already revoked
        if cert_request.get('is_revoked', False):
            return jsonify({'error': 'Certificate is already revoked'}), 400
        
        # Revoke the certificate
        result = revoke_certificate(cert_id, session['user_id'], revocation_reason)
        
        if result:
            create_audit_log(
                session['user_id'],
                'certificate_revoked',
                resource='certificate_request',
                status='success',
                details=f'Certificate {cert_id} revoked. Reason: {revocation_reason}'
            )
            
            print(f"\n{'='*60}")
            print(f"🔒 CERTIFICATE REVOKED")
            print(f"{'='*60}")
            print(f"Certificate ID: {cert_id}")
            print(f"Revoked By: {session['email']}")
            print(f"Reason: {revocation_reason}")
            print(f"{'='*60}\n")
            
            return jsonify({
                'success': True,
                'message': 'Certificate revoked successfully',
                'cert_id': str(cert_id)
            }), 200
        else:
            return jsonify({'error': 'Failed to revoke certificate'}), 500
    
    except Exception as e:
        print(f"❌ Certificate Revocation Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/view-certificate/<cert_id>')
@certificate_owner_only
def view_certificate(cert_id):
    """View certificate with client-side decryption (Owner only - RBAC enforced by decorator)"""
    try:
        # cert_id is already decoded and ownership verified by @certificate_owner_only decorator
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return render_template('404.html'), 404
        
        # Phase 10: Check certificate status (expired/revoked)
        status_check = check_certificate_status(cert_id)
        if not status_check['is_valid']:
            create_audit_log(
                session['user_id'],
                'certificate_access_blocked_invalid_status',
                resource='certificate_request',
                status='failure',
                details=f'Certificate {cert_id} is {status_check["status"]}: {status_check["reason"]}'
            )
            return render_template('403.html', message=f'Certificate is {status_check["status"]}: {status_check["reason"]}'), 403
        
        # Check if certificate is approved
        if cert_request['status'] != 'approved':
            return render_template('403.html', message='Certificate is not yet approved'), 403
        
        # Get encrypted content (client-side encrypted)
        encrypted_data = cert_request.get('certificate_content')
        if not encrypted_data:
            # Load from file if not in DB
            filepath = cert_request.get('encrypted_file_path')
            if not filepath:
                return render_template('403.html', message='Certificate file not found'), 403
            encrypted_bytes = load_encrypted_certificate(filepath)
            if not encrypted_bytes:
                return render_template('403.html', message='Failed to load certificate'), 403
            encrypted_data = encrypted_bytes.decode('utf-8')
        
        # Verify signature exists (Phase 7)
        signature_hex = cert_request.get('certificate_signature')
        if not signature_hex:
            create_audit_log(
                session['user_id'],
                'certificate_access_blocked_no_signature',
                resource='certificate_request',
                status='failure',
                details=f'Certificate {cert_id} has no signature - integrity check failed'
            )
            return render_template('403.html', message='🚨 Certificate integrity compromised - No signature found'), 403
        
        create_audit_log(
            session['user_id'],
            'certificate_viewed',
            resource='certificate_request',
            status='success',
            details=f'Certificate {cert_id} sent for CLIENT-SIDE decryption'
        )
        
        # Pass encrypted data to template for client-side decryption
        return render_template('view_certificate_decrypted.html', 
                             encrypted_data=encrypted_data,
                             signature=signature_hex,
                             cert_id=encode_cert_id(str(cert_id)),
                             session_data=session)
    
    except Exception as e:
        print(f"❌ Certificate View Error: {str(e)}")
        return render_template('500.html'), 500


@app.route('/download-certificate/<cert_id>')
@certificate_owner_only
def download_certificate(cert_id):
    """Download encrypted certificate data for client-side decryption (Owner only - RBAC enforced by decorator)"""
    try:
        # cert_id is already decoded and ownership verified by @certificate_owner_only decorator
        cert_request = certificate_requests_collection.find_one({'_id': cert_id})
        if not cert_request:
            return jsonify({'error': 'Certificate not found'}), 404
        
        # Phase 10: Check certificate status (expired/revoked)
        status_check = check_certificate_status(cert_id)
        if not status_check['is_valid']:
            create_audit_log(
                session['user_id'],
                'certificate_download_blocked_invalid_status',
                resource='certificate_request',
                status='failure',
                details=f'Certificate {cert_id} is {status_check["status"]}: {status_check["reason"]}'
            )
            return jsonify({'error': f'Certificate is {status_check["status"]}: {status_check["reason"]}'}), 403
        
        # Check if approved
        if cert_request['status'] != 'approved':
            return jsonify({'error': 'Certificate not approved'}), 403
        
        # Get encrypted content (client-side encrypted)
        encrypted_data = cert_request.get('certificate_content')
        if not encrypted_data:
            encrypted_bytes = load_encrypted_certificate(cert_request.get('encrypted_file_path'))
            if not encrypted_bytes:
                return jsonify({'error': 'Failed to load certificate'}), 500
            encrypted_data = encrypted_bytes.decode('utf-8')
        
        # Verify signature exists (Phase 7)
        signature_hex = cert_request.get('certificate_signature')
        if not signature_hex:
            create_audit_log(
                session['user_id'],
                'certificate_download_blocked_no_signature',
                resource='certificate_request',
                status='failure',
                details=f'Certificate {cert_id} has no signature - integrity check failed'
            )
            return jsonify({'error': '🚨 Certificate integrity compromised - No signature found'}), 403
        
        create_audit_log(
            session['user_id'],
            'certificate_downloaded',
            resource='certificate_request',
            details=f'Certificate {cert_id} downloaded for CLIENT-SIDE decryption'
        )
        
        # Return encrypted data as JSON for client-side decryption
        return jsonify({
            'success': True,
            'encrypted_data': encrypted_data,
            'signature': signature_hex,
            'cert_id': str(cert_id)
        }), 200
    
    except Exception as e:
        print(f"❌ Certificate Download Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# Error Handlers
# ============================================

@app.errorhandler(404)
def not_found(error):
    """404 Error Handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    """500 Error Handler"""
    return render_template('500.html'), 500


# ============================================
# Main Entry Point
# ============================================

if __name__ == '__main__':
    # Initialize MongoDB
    initialize_mongodb()
    
    print(f"\n{'='*60}")
    print(f"🚀 Secure Certificate Authority - MongoDB Edition")
    print(f"{'='*60}")
    print(f"Flask Server Starting...")
    print(f"URL: http://localhost:9000")
    print(f"Database: MongoDB (Local)")
    print(f"{'='*60}\n")
    
    app.run(debug=True, host='localhost', port=9000)
