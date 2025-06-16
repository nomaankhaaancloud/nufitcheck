import os
import jwt
import random
from datetime import datetime, timedelta
from typing import Optional, Dict
from dotenv import load_dotenv

load_dotenv()

# JWT Configuration
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-this-in-production')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '1440'))  # 24 hours
# Add these new functions to your key_func.py file
# Reset token configuration (shorter expiry than access tokens)
RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv('RESET_TOKEN_EXPIRE_MINUTES', '10'))  # 10 minutes

def create_reset_token(email: str) -> str:
    """Create a temporary JWT token for password reset (short-lived)"""
    to_encode = {
        "sub": email,
        "type": "password_reset",
        "exp": datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow()
    }
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Error creating reset token: {e}")
        return None

def verify_reset_token(token: str) -> Optional[str]:
    """Verify reset token and return email if valid"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Check if it's a password reset token
        if payload.get("type") != "password_reset":
            print("Token is not a password reset token")
            return None
            
        return payload.get("sub")  # Return email
        
    except jwt.ExpiredSignatureError:
        print("Reset token has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid reset token")
        return None
    except Exception as e:
        print(f"Error verifying reset token: {e}")
        return None

def get_token_expiry_time(token: str) -> Optional[datetime]:
    """Get token expiry time without verifying signature"""
    try:
        # Decode without verification to get expiry time
        payload = jwt.decode(token, options={"verify_signature": False})
        exp_timestamp = payload.get("exp")
        if exp_timestamp:
            return datetime.utcfromtimestamp(exp_timestamp)
        return None
    except Exception as e:
        print(f"Error getting token expiry: {e}")
        return None

def create_access_token(data: Dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Error creating access token: {e}")
        return None

def generate_4_digit_code() -> str:
    """Generate a random 4-digit code for password reset"""
    try:
        # Generate a random 4-digit number (1000-9999)
        code = random.randint(1000, 9999)
        return str(code)
    except Exception as e:
        print(f"Error generating 4-digit code: {e}")
        return None

def verify_token(token: str) -> Optional[Dict]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None

def get_current_user_email(token: str) -> Optional[str]:
    """Extract user email from token"""
    payload = verify_token(token)
    if payload:
        return payload.get("sub")
    return None

import secrets
import pyotp

def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def verify_mfa_token(secret: str, token: str) -> bool:
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    except Exception as e:
        print(f"Error verifying MFA token: {e}")
        return False

def generate_backup_codes(count: int = 10) -> list:
    return [secrets.token_hex(4).upper() for _ in range(count)]

def create_access_token_with_mfa(data: Dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire, 
        "iat": datetime.utcnow(),
        "mfa_verified": data.get("mfa_verified", False)
    })
    
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Error creating access token with MFA: {e}")
        return None