from pymongo import MongoClient
import hashlib
import secrets
from datetime import datetime

client = MongoClient('mongodb://localhost:27017/')
db = client['certificate_authority']

# Hash password function
def hash_password(password):
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return password_hash, salt

# Delete old admin and create your admin
db.users.delete_many({})

password_hash, password_salt = hash_password('AdminSecure@2026')

db.users.insert_one({
    'full_name': 'Gugan Saravanan',
    'email': 'gugansaravanan3007@gmail.com',
    'phone_number': '+919150158370',
    'password_hash': password_hash,
    'password_salt': password_salt,
    'role': 'admin',
    'status': 'active',
    'created_at': datetime.utcnow(),
    'is_verified': True
})

print('✅ Admin account created!')
print()
print('='*50)
print('🔐 YOUR ADMIN CREDENTIALS')
print('='*50)
print('Email: gugansaravanan3007@gmail.com')
print('Password: AdminSecure@2026')
print('Phone: +919150158370')
print('='*50)
