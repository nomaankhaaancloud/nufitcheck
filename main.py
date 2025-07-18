from fastapi import FastAPI, File, UploadFile, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Body
from pydantic import BaseModel, EmailStr
import shutil
import os
import uuid
import json
from datetime import datetime, timedelta
from frame_split import extract_frames
from gpt import chat_with_gpt, load_image_messages
from database import DatabaseManager
from utils.mailservice import send_password_reset_email, log_password_reset_code
from utils.authmiddleware import get_current_user, get_optional_current_user, get_authenticated_user
from utils.key_func import create_access_token, generate_4_digit_code, create_access_token_with_mfa, create_temp_mfa_token, generate_backup_codes
from utils.voiceagent import generate_audio, speech_to_text_stream
from dotenv import load_dotenv
import base64
from utils.key_func import SECRET_KEY, ALGORITHM
import jwt
from jwt import PyJWTError as JWTError 
from fastapi import Form, File, UploadFile
from utils.voiceagent import speech_to_text, generate_response_audio_base64
import random
import string
from fastapi.middleware.cors import CORSMiddleware
import logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
db = DatabaseManager()


UPLOAD_DIR = "uploads"
FRAME_DIR = "extracted_frames"
# AUDIO_DIR = "audio_files"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(FRAME_DIR, exist_ok=True)
# os.makedirs(AUDIO_DIR, exist_ok=True)

# Updated Pydantic model
class UserSignup(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

class ValidateCodeRequest(BaseModel):
    email: EmailStr
    code: str

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

class SetNewPasswordRequest(BaseModel):
    reset_token: str
    new_password: str

# Updated Pydantic Models
from pydantic import BaseModel, EmailStr
from typing import Optional

class MFASetupRequest(BaseModel):
    phone_number: str  # Format: +1234567890

class MFAVerifyRequest(BaseModel):
    token: str

class MFALoginRequest(BaseModel):
    email: EmailStr
    password: str

class MFATokenVerifyRequest(BaseModel):
    temp_token: str
    mfa_token: str

class MFADisableRequest(BaseModel):
    password: str



def generate_response_audio_base64(text_content, scan_id, message_type="analysis"):
    """Generate audio as base64-encoded string without saving to disk"""
    try:
        print(f"Starting audio generation for {message_type} with scan_id: {scan_id}")
        
        # Extract appropriate text for audio generation
        if message_type == "analysis":
            audio_text = extract_analysis_fields_from_json(text_content)
        else:
            audio_text = text_content[:1500] if len(text_content) > 1500 else text_content
        
        print(f"Audio text extracted: {audio_text[:50]}...")

        # Call generate_audio and receive audio bytes directly (no file writing)
        audio_bytes = generate_audio(text=audio_text)

        if audio_bytes:
            audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
            audio_filename = f"{scan_id}_{message_type}_{uuid.uuid4().hex[:8]}.mp3"

            return {
                "audio_base64": audio_base64,
                "audio_format": "audio/mpeg",
                "filename": audio_filename
            }
        else:
            print(f"Audio generation failed for {message_type}")
            return None

    except Exception as e:
        print(f"Error generating audio: {e}")
        import traceback
        traceback.print_exc()
        return None


def extract_analysis_fields_from_json(json_text):
    """Extract fit_score, fit_line, stylist_says, and what_went_wrong from JSON response for audio generation"""
    try:
        # Clean the response by removing markdown code blocks if present
        cleaned_text = json_text.strip()
        if cleaned_text.startswith('```json'):
            cleaned_text = cleaned_text[7:]  # Remove ```json
        if cleaned_text.endswith('```'):
            cleaned_text = cleaned_text[:-3]  # Remove ```
        cleaned_text = cleaned_text.strip()
        
        parsed = json.loads(cleaned_text)
        
        # Extract all relevant fields (check both possible field names)
        fit_score = parsed.get('fit_score', '') or parsed.get('score', '') or parsed.get('numeric_score', '')
        fit_line = parsed.get('fit_line', '')
        stylist_says = parsed.get('stylist_says', '')
        what_went_wrong = parsed.get('what_went_wrong', '')
        
        # Build comprehensive audio text
        audio_parts = []
        
        # Add fit score if available
        if fit_score:
            if isinstance(fit_score, (int, float)):
                audio_parts.append(f"Your outfit scores {fit_score} out of 100.")
            elif isinstance(fit_score, str) and '/' in fit_score:
                # Handle "85/100" format
                audio_parts.append(f"Your outfit scores {fit_score}.")
            else:
                audio_parts.append(f"Your outfit score is {fit_score}.")
        
        # Add fit line (main assessment)
        if fit_line:
            audio_parts.append(fit_line)
        
        # Add stylist advice
        if stylist_says:
            audio_parts.append(f"Style advice: {stylist_says}")
        
        # Add what went wrong (if any issues)
        if what_went_wrong:
            audio_parts.append(f"Areas for improvement: {what_went_wrong}")
        
        # Join all parts with appropriate spacing
        if audio_parts:
            combined_text = " ".join(audio_parts)
            print(f"Combined audio text from analysis: {combined_text[:100]}...")
            
            # Limit total length to avoid overly long audio
            max_length = 1500
            if len(combined_text) > max_length:
                combined_text = combined_text[:max_length] + "..."
            
            return combined_text
        else:
            # Fallback if no recognized fields found
            fallback_text = json_text[:200] if len(json_text) > 200 else json_text
            print(f"No analysis fields found, using fallback: {fallback_text[:50]}...")
            return fallback_text
                
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        # If not JSON, try to extract meaningful text for audio
        fallback_text = json_text[:200] if len(json_text) > 200 else json_text
        print(f"Using fallback text due to JSON error: {fallback_text[:50]}...")
        return fallback_text
    except Exception as e:
        print(f"Unexpected error in extract_analysis_fields_from_json: {e}")
        fallback_text = json_text[:200] if len(json_text) > 200 else json_text
        return fallback_text


def extract_fit_line_from_json(json_text):
    """Legacy function - kept for backward compatibility"""
    # This function is now deprecated but kept to avoid breaking existing code
    # It will call the new comprehensive extraction function
    return extract_analysis_fields_from_json(json_text)

@app.post("/auth/signup", response_model=AuthResponse)
async def signup(user_data: UserSignup):
    """User registration endpoint"""
    try:
        # Validate password length
        if len(user_data.password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 6 characters long"
            )
        
        # Create authenticated user
        auth_success = db.create_auth_user(user_data.email, user_data.password)
        if not auth_success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Get user data immediately after creation
        user = db.get_auth_user_by_email(user_data.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve user after creation"
            )
        
        # Create user profile for outfit analysis
        user_id = str(uuid.uuid4())
        profile_success = db.create_user(user_id, user_data.email)
        
        if not profile_success:
            print(f"Warning: Failed to create user profile for {user_data.email}")
        
        # Create access token
        access_token = create_access_token(data={"sub": user_data.email})
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create access token"
            )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],  # This should now be a string
                "email": user["email"],
                "created_at": user["created_at"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Detailed signup error: {str(e)}")  # Add more detailed logging
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@app.post("/auth/login", response_model=AuthResponse)
async def login(user_data: UserLogin):
    """User login endpoint"""
    try:
        # Authenticate user
        user = db.authenticate_user(user_data.email, user_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        # Create access token
        access_token = create_access_token(data={"sub": user["email"]})
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create access token"
            )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "created_at": user["created_at"]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@app.post("/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Request password reset with 4-digit code"""
    try:
        # Check if user exists
        user = db.get_auth_user_by_email(request.email)
        if not user:
            # Don't reveal if email exists or not for security
            return {"message": "If the email exists, a password reset code has been sent"}

        # Check if there are already active codes for this email
        active_codes_count = db.get_active_reset_codes_count(request.email)
        if active_codes_count >= 3:  # Limit to 3 active codes per email
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many active reset codes. Please wait before requesting a new one."
            )

        # Clean up old codes for this email first
        db.cleanup_codes_for_email(request.email)

        # Generate 4-digit code
        reset_code = generate_4_digit_code()
        if not reset_code:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate reset code"
            )

        # Store code in database (expires in 15 minutes)
        from datetime import timezone
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        code_stored = db.create_password_reset_code(request.email, reset_code, expires_at)
        
        if not code_stored:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store reset code"
            )

        # Try to send email with code
        email_sent = send_password_reset_email(request.email, reset_code)
        
        if not email_sent:
            # Fallback: log to console if email service not configured
            log_password_reset_code(request.email, reset_code)
            print("Email service not configured, reset code logged to console")

        return {
            "message": "If the email exists, a password reset code has been sent",
            "expires_in": 900  # 15 minutes in seconds
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password reset request failed: {str(e)}"
        )

@app.post("/auth/validate-reset-code")
async def validate_reset_code(request: ValidateCodeRequest):
    """Validate password reset code and return temporary token"""
    try:
        # Check if user exists
        user = db.get_auth_user_by_email(request.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or code"
            )

        # Verify code for the specific email
        verified_email = db.verify_password_reset_code_for_email(request.email, request.code)
        if not verified_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset code"
            )

        # Create a temporary reset token (short-lived, 10 minutes)
        from utils.key_func import create_reset_token
        reset_token = create_reset_token(request.email)
        if not reset_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create reset token"
            )

        return {
            "message": "Code validated successfully",
            "reset_token": reset_token,
            "expires_in": 600  # 10 minutes in seconds
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code validation failed: {str(e)}"
        )

@app.post("/auth/reset-password")
async def reset_password(request: ResetPasswordRequest):
    """Reset password with email, code, and new password (one-step process)"""
    try:
        # Validate new password
        if len(request.new_password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 6 characters long"
            )

        # Check if user exists
        user = db.get_auth_user_by_email(request.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or code"
            )

        # Verify code for the specific email
        verified_email = db.verify_password_reset_code_for_email(request.email, request.code)
        if not verified_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset code"
            )

        # Update password
        password_updated = db.update_password(request.email, request.new_password)
        if not password_updated:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )

        # Mark code as used
        db.mark_code_as_used(request.code)

        return {"message": "Password reset successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password reset failed: {str(e)}"
        )

@app.post("/auth/set-new-password")
async def set_new_password(request: SetNewPasswordRequest):
    """Set new password using temporary reset token (two-step process)"""
    try:
        # Validate new password
        if len(request.new_password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 6 characters long"
            )

        # Verify reset token and get email
        from utils.key_func import verify_reset_token
        email = verify_reset_token(request.reset_token)
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )

        # Update password
        password_updated = db.update_password(email, request.new_password)
        if not password_updated:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password"
            )

        return {"message": "Password updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password update failed: {str(e)}"
        )

@app.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_authenticated_user)):
    """Get current user information"""
    return {
        "user": {
            "id": current_user["id"],
            "email": current_user["email"],
            "created_at": current_user["created_at"]
        }
    }

# Twilio SMS Service with PostgreSQL storage for OTP codes
import os
import random
import string
from twilio.rest import Client
from datetime import datetime, timedelta

class TwilioSMSService:
    def __init__(self, db_connection):
        self.is_development = os.getenv('ENVIRONMENT', 'production') == 'development'
        self.db = db_connection  # Pass the database connection instance
        
        # Only initialize Twilio client if not in development mode
        if not self.is_development:
            self.client = Client(
                os.getenv('TWILIO_ACCOUNT_SID'),
                os.getenv('TWILIO_AUTH_TOKEN')
            )
            self.from_number = os.getenv('TWILIO_PHONE_NUMBER')
        else:
            self.client = None
            self.from_number = None
    
    def generate_otp(self) -> str:
        """Generate a 6-digit OTP"""
        return ''.join(random.choices(string.digits, k=6))
    
    def send_otp(self, phone_number: str, otp: str) -> bool:
        """Send OTP via SMS"""
        try:
            # In development mode, just log the OTP instead of sending SMS
            if self.is_development:
                print(f"[DEV MODE] SMS OTP for {phone_number}: {otp}")
                print(f"[DEV MODE] Environment check - ENVIRONMENT={os.getenv('ENVIRONMENT')}")
                return True
            
            if not self.client or not self.from_number:
                print("Error: Twilio client not initialized")
                return False
                
            message = self.client.messages.create(
                body=f"Your verification code is: {otp}. This code will expire in 5 minutes.",
                from_=self.from_number,
                to=phone_number
            )
            return True
        except Exception as e:
            print(f"Error sending SMS: {e}")
            return False
    
    def store_otp(self, user_email: str, otp: str, expires_in: int = 300) -> bool:
        """Store OTP in PostgreSQL with expiration (default 5 minutes)"""
        try:
            if not self.db.connect():
                return False
            
            # Calculate expiration time
            expiration_time = datetime.now() + timedelta(seconds=expires_in)
            
            cursor = self.db.connection.cursor()
            cursor.execute('''
                INSERT INTO mfa_otp_codes (user_email, otp_code, expires_at, created_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_email) DO UPDATE SET
                    otp_code = EXCLUDED.otp_code,
                    expires_at = EXCLUDED.expires_at,
                    created_at = EXCLUDED.created_at
            ''', (user_email, otp, expiration_time, datetime.now()))
            cursor.close()
            return True
        except Exception as e:
            print(f"Error storing OTP: {e}")
            return False
    
    def verify_otp(self, user_email: str, provided_otp: str) -> bool:
        """Verify OTP and remove it after successful verification"""
        try:
            if not self.db.connect():
                return False
            
            cursor = self.db.connection.cursor()
            
            # Get the stored OTP and check if it's not expired
            cursor.execute('''
                SELECT otp_code FROM mfa_otp_codes 
                WHERE user_email = %s AND expires_at > %s
            ''', (user_email, datetime.now()))
            
            result = cursor.fetchone()
            
            if result and result[0] == provided_otp:
                # Delete the OTP after successful verification
                cursor.execute('DELETE FROM mfa_otp_codes WHERE user_email = %s', (user_email,))
                cursor.close()
                return True
            
            cursor.close()
            return False
        except Exception as e:
            print(f"Error verifying OTP: {e}")
            return False
    
    def cleanup_expired_otps(self) -> bool:
        """Clean up expired OTP codes (can be called periodically)"""
        try:
            if not self.db.connect():
                return False
            
            cursor = self.db.connection.cursor()
            cursor.execute('DELETE FROM mfa_otp_codes WHERE expires_at < %s', (datetime.now(),))
            deleted_count = cursor.rowcount
            cursor.close()
            print(f"Cleaned up {deleted_count} expired OTP codes")
            return True
        except Exception as e:
            print(f"Error cleaning up expired OTPs: {e}")
            return False
# Initialize the SMS service

sms_service = TwilioSMSService(db)

# Updated MFA Endpoints (same as before, but now using PostgreSQL)
@app.post("/auth/mfa/setup")
async def setup_mfa(request: MFASetupRequest, current_user: dict = Depends(get_authenticated_user)):
    try:
        user_email = current_user["email"]
        
        if db.is_mfa_enabled(user_email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is already enabled"
            )

        # Validate phone number format (basic validation)
        if not request.phone_number.startswith('+'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number must include country code (e.g., +1234567890)"
            )

        # Store phone number in database
        success = db.create_mfa_phone(user_email, request.phone_number)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to setup MFA"
            )

        # Generate and send OTP for verification
        otp = sms_service.generate_otp()
        
        if not sms_service.send_otp(request.phone_number, otp):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification SMS"
            )
        
        # Store OTP for verification
        sms_service.store_otp(user_email, otp)

        return {
            "message": "Verification SMS sent to your phone number",
            "phone_number": request.phone_number[-4:]  # Show only last 4 digits
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"MFA setup failed: {str(e)}"
        )

@app.post("/auth/mfa/verify")
async def verify_mfa_setup(
    request: MFAVerifyRequest,
    current_user: dict = Depends(get_authenticated_user)
):
    try:
        user_email = current_user["email"]
        phone_number = db.get_mfa_phone(user_email)
        
        if not phone_number:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not set up"
            )

        # Verify OTP
        if not sms_service.verify_otp(user_email, request.token):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        # Generate backup codes
        backup_codes = generate_backup_codes()
        backup_codes_str = ','.join(backup_codes)
        
        # Enable MFA and store backup codes
        db.enable_mfa(user_email)
        db.store_backup_codes(user_email, backup_codes_str)

        return {
            "message": "MFA enabled successfully",
            "backup_codes": backup_codes
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"MFA verification failed: {str(e)}"
        )

@app.post("/auth/mfa/login")
async def mfa_login_step1(request: MFALoginRequest):
    """Step 1: Validate email/password and send SMS OTP"""
    try:
        user = db.authenticate_user(request.email, request.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        if not db.is_mfa_enabled(request.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not enabled for this account"
            )

        # Get user's phone number
        phone_number = db.get_mfa_phone(request.email)
        if not phone_number:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="MFA phone number not found"
            )

        # Generate and send OTP
        otp = sms_service.generate_otp()
        
        if not sms_service.send_otp(phone_number, otp):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification SMS"
            )
        
        # Store OTP for verification
        sms_service.store_otp(request.email, otp)

        # Create a temporary token for MFA verification
        temp_token = create_temp_mfa_token(
            data={"sub": user["email"], "purpose": "mfa_verification"}
        )
        
        return {
            "temp_token": temp_token,
            "message": "Verification SMS sent to your phone",
            "phone_number": phone_number[-4:],  # Show only last 4 digits
            "requires_mfa": True
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"MFA login step 1 failed: {str(e)}"
        )

@app.post("/auth/mfa/verify-token")
async def mfa_login_step2(request: MFATokenVerifyRequest):
    """Step 2: Verify SMS OTP and return access token"""
    try:
        # Verify the temporary token
        try:
            payload = jwt.decode(request.temp_token, SECRET_KEY, algorithms=[ALGORITHM])
            email = payload.get("sub")
            purpose = payload.get("purpose")
            
            if purpose != "mfa_verification":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid temporary token"
                )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired temporary token"
            )

        # Get user
        user = db.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        # Verify OTP or backup code
        otp_valid = sms_service.verify_otp(email, request.mfa_token)
        backup_valid = db.use_backup_code(email, request.mfa_token)
        
        if not (otp_valid or backup_valid):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP or backup code"
            )

        # Create final access token
        access_token = create_access_token_with_mfa(
            data={"sub": user["email"], "mfa_verified": True}
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "created_at": user["created_at"]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"MFA token verification failed: {str(e)}"
        )

@app.post("/auth/mfa/disable")
async def disable_mfa(
    request: MFADisableRequest,
    current_user: dict = Depends(get_authenticated_user)
):
    try:
        user_email = current_user["email"]
        
        user = db.authenticate_user(user_email, request.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password"
            )

        success = db.disable_mfa(user_email)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to disable MFA"
            )

        return {"message": "MFA disabled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"MFA disable failed: {str(e)}"
        )

@app.get("/auth/mfa/status")
async def get_mfa_status(current_user: dict = Depends(get_authenticated_user)):
    try:
        user_email = current_user["email"]
        is_enabled = db.is_mfa_enabled(user_email)
        phone_number = db.get_mfa_phone(user_email) if is_enabled else None
        
        return {
            "mfa_enabled": is_enabled,
            "phone_number": phone_number[-4:] if phone_number else None
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get MFA status: {str(e)}"
        )

# Optional: Add a cleanup endpoint to remove expired OTPs
@app.post("/auth/mfa/cleanup")
async def cleanup_expired_otps():
    """Clean up expired OTP codes (can be called by a cron job)"""
    try:
        success = sms_service.cleanup_expired_otps()
        if success:
            return {"message": "Expired OTP codes cleaned up successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to cleanup expired OTPs"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cleanup failed: {str(e)}"
        )
















import asyncio
import json
import uuid
import os
import shutil
import re
import base64
import traceback
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect, FastAPI, Query
from fastapi.responses import JSONResponse
import logging
import io
import threading
import queue
import time
from datetime import datetime

logger = logging.getLogger(__name__)

class StreamingTranscriber:
    def __init__(self, scan_id: str, user_email: str, manager):
        self.scan_id = scan_id
        self.user_email = user_email
        self.manager = manager
        self.audio_buffer = io.BytesIO()
        self.is_recording = False
        self.transcription_queue = queue.Queue()
        self.processing_thread = None
        
    def add_audio_chunk(self, audio_chunk: bytes):
        self.audio_buffer.write(audio_chunk)
        self.last_chunk_time = time.time()
        
        if not self.is_recording:
            self.is_recording = True
            self.start_processing_thread()
    
    def start_processing_thread(self):
        if self.processing_thread and self.processing_thread.is_alive():
            return
            
        self.processing_thread = threading.Thread(target=self._process_audio_continuously)
        self.processing_thread.daemon = True
        self.processing_thread.start()
    
    def _process_audio_continuously(self):
        while self.is_recording:
            time.sleep(0.1)
    
    async def _transcribe_and_respond(self, audio_data: bytes):
        try:
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "transcribing",
                "message": "Converting speech to text...",
                "timestamp": datetime.now().isoformat()
            })
            
            transcription = speech_to_text_stream(audio_data)
            
            if not transcription or not transcription.strip():
                await self.manager.send_message(self.scan_id, self.user_email, {
                    "type": "transcription_empty",
                    "message": "No speech detected"
                })
                return
            
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "transcription",
                "message": transcription,
                "timestamp": datetime.now().isoformat()
            })
            
            await self._generate_chat_response(transcription)
            
        except Exception as e:
            logger.error(f"Error in transcribe and respond: {e}")
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "error",
                "message": f"Error processing audio: {str(e)}"
            })
    
    async def _generate_chat_response(self, user_message: str):
        try:
            db = DatabaseManager()
            
            db.add_chat_message(self.scan_id, "user", user_message)
            
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "generating",
                "message": "Generating response...",
                "timestamp": datetime.now().isoformat()
            })
            
            chat_history = db.get_chat_history(self.scan_id)
            
            filtered_history = []
            original_analysis = None
            
            for msg in chat_history:
                if msg["role"] == "system":
                    continue
                elif msg["role"] == "assistant" and msg["message"].startswith("{"):
                    original_analysis = msg["message"]
                    continue
                else:
                    filtered_history.append({
                        "role": msg["role"],
                        "content": msg["message"]
                    })
            
            chat_system_message = {
                "role": "system",
                "content": (
                    "You are NuFit — a fun, stylish fashion AI assistant. "
                    "You are now in REAL-TIME VOICE CHAT MODE. "
                    "IMPORTANT: Do NOT return JSON responses. Respond naturally in conversation. "
                    "Keep responses very concise (1-2 sentences max) for real-time voice chat. "
                    "Speak like a cool, supportive friend who knows fashion. "
                    "Be helpful, encouraging, and give practical fashion advice. "
                    "You previously analyzed this user's outfit and gave them a score. "
                    "Reference that analysis when relevant, but respond conversationally. "
                    "If user asks anything unrelated to fashion or styling tips, tell user to stick to the topic. "
                )
            }
            
            gpt_messages = [chat_system_message]
            
            if original_analysis:
                try:
                    parsed_analysis = json.loads(original_analysis.strip())
                    context_message = {
                        "role": "assistant",
                        "content": f"I previously analyzed your outfit and gave you a {parsed_analysis.get('score', 'N/A')} score. {parsed_analysis.get('stylist_says', '')}"
                    }
                    gpt_messages.append(context_message)
                except:
                    gpt_messages.append({
                        "role": "assistant", 
                        "content": "I previously analyzed your outfit and provided feedback."
                    })
            
            gpt_messages.extend(filtered_history[-10:])
            
            reply = chat_with_gpt(gpt_messages, max_tokens=100)
            
            if not reply:
                await self.manager.send_message(self.scan_id, self.user_email, {
                    "type": "error",
                    "message": "Failed to generate response"
                })
                return
            
            db.add_chat_message(self.scan_id, "assistant", reply)
            
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "response",
                "message": reply,
                "timestamp": datetime.now().isoformat()
            })
            
            asyncio.create_task(self._generate_and_send_audio_stream(reply))
            
        except Exception as e:
            logger.error(f"Error generating chat response: {e}")
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "error",
                "message": f"Error generating response: {str(e)}"
            })
    
    async def _generate_and_send_audio_stream(self, text: str):
        try:
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "generating_audio",
                "message": "Generating audio response",
                "timestamp": datetime.now().isoformat()
            })
            
            async for audio_chunk in generate_audio_stream(text, self.scan_id):
                if audio_chunk:
                    await self.manager.send_message(self.scan_id, self.user_email, {
                        "type": "audio_chunk",
                        "audio_base64": audio_chunk["audio_base64"],
                        "chunk_index": audio_chunk["chunk_index"],
                        "is_final": audio_chunk["is_final"],
                        "timestamp": datetime.now().isoformat()
                    })
            
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "audio_complete",
                "text": text,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error generating streaming audio: {e}")
            await self.manager.send_message(self.scan_id, self.user_email, {
                "type": "audio_error",
                "message": f"Audio generation failed: {str(e)}"
            })

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_sessions: Dict[str, Dict] = {}
        self.transcribers: Dict[str, StreamingTranscriber] = {}
        

    async def connect(self, websocket: WebSocket, scan_id: str, user_email: str):
        await websocket.accept()
        connection_id = f"{user_email}_{scan_id}"
        self.active_connections[connection_id] = websocket
        self.user_sessions[connection_id] = {
            "scan_id": scan_id,
            "user_email": user_email,
            "connected_at": datetime.now(),
            "is_processing": False,
            "is_streaming": False
        }
        
        self.transcribers[connection_id] = StreamingTranscriber(scan_id, user_email, self)
        
        logger.info(f"WebSocket connected: {connection_id}")

    def disconnect(self, scan_id: str, user_email: str):
        connection_id = f"{user_email}_{scan_id}"
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        if connection_id in self.user_sessions:
            del self.user_sessions[connection_id]
        if connection_id in self.transcribers:
            # Stop any ongoing transcription
            transcriber = self.transcribers[connection_id]
            transcriber.is_recording = False
            del self.transcribers[connection_id]
        logger.info(f"WebSocket disconnected: {connection_id}")

    async def send_message(self, scan_id: str, user_email: str, message: dict):
        connection_id = f"{user_email}_{scan_id}"
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            try:
                # Check if websocket is still connected before sending
                if websocket.client_state.name == "CONNECTED":
                    await websocket.send_text(json.dumps(message))
                else:
                    print(f"[DEBUG] WebSocket {connection_id} is not connected, removing from active connections")
                    self.disconnect(scan_id, user_email)
            except Exception as e:
                logger.error(f"Error sending message to {connection_id}: {e}")
                self.disconnect(scan_id, user_email)

    def is_processing(self, scan_id: str, user_email: str) -> bool:
        connection_id = f"{user_email}_{scan_id}"
        return self.user_sessions.get(connection_id, {}).get("is_processing", False)

    def set_processing(self, scan_id: str, user_email: str, processing: bool):
        connection_id = f"{user_email}_{scan_id}"
        if connection_id in self.user_sessions:
            self.user_sessions[connection_id]["is_processing"] = processing
    
    def is_streaming(self, scan_id: str, user_email: str) -> bool:
        connection_id = f"{user_email}_{scan_id}"
        return self.user_sessions.get(connection_id, {}).get("is_streaming", False)

    def set_streaming(self, scan_id: str, user_email: str, streaming: bool):
        connection_id = f"{user_email}_{scan_id}"
        if connection_id in self.user_sessions:
            self.user_sessions[connection_id]["is_streaming"] = streaming
    
    def get_transcriber(self, scan_id: str, user_email: str) -> Optional[StreamingTranscriber]:
        connection_id = f"{user_email}_{scan_id}"
        return self.transcribers.get(connection_id)

manager = ConnectionManager()

async def get_websocket_user(token: str) -> Optional[Dict]:
    try:
        print(f"[DEBUG] Decoding token: {token}")
        if not token:
            print("[ERROR] No token provided")
            return None
        
        payload = verify_token(token)
        print(f"[DEBUG] Decoded payload: {payload}")
        
        if not payload:
            return None
        
        email = payload.get("sub")
        if not email:
            return None
        
        db = DatabaseManager()
        user = db.get_auth_user_by_email(email)
        if not user:
            return None
        
        mfa_required = payload.get("mfa_required", False)
        mfa_verified = payload.get("mfa_verified", False)
        
        if mfa_required and not mfa_verified:
            print("[ERROR] MFA required but not verified")
            return None
        return user
    
    except Exception as e:
        logger.error(f"WebSocket auth error: {e}")
        return None

@app.websocket("/ws/chat/{scan_id}")
async def websocket_chat_endpoint(websocket: WebSocket, scan_id: str, token: str = Query(...)):
    print(f"[DEBUG] Incoming WebSocket connection for scan_id: {scan_id}")
    print(f"[DEBUG] Token received: {token}")
    
    user_email = None
    connection_id = None
    
    try:
        # Accept the WebSocket connection first
        await websocket.accept()
        print("[DEBUG] WebSocket connection accepted")
        
        # Then perform authentication
        current_user = await get_websocket_user(token)
        print(f"[DEBUG] Authenticated user from token: {current_user}")
        
        if not current_user:
            print("[ERROR] Authentication failed.")
            await websocket.close(code=1008, reason="Authentication failed")
            return
        
        user_email = current_user["email"]
        connection_id = f"{user_email}_{scan_id}"
        
        # Initialize DatabaseManager
        db = DatabaseManager()
        
        # Get scan information
        scan = db.get_scan(scan_id)
        if not scan:
            print(f"[ERROR] Scan not found: {scan_id}")
            await websocket.close(code=1008, reason="Scan not found")
            return
        
        # Get user profile
        user_profile = db.get_user(scan["user_id"])
        if not user_profile:
            print(f"[ERROR] User profile not found for user_id: {scan['user_id']}")
            await websocket.close(code=1008, reason="User profile not found")
            return
        
        print(f"[DEBUG] User profile found: {user_profile}")
        print(f"[DEBUG] Comparing emails - Profile: {user_profile['email']}, Token: {user_email}")
        
        # Check if the authenticated user owns this scan
        if user_profile["email"] != user_email:
            print(f"[ERROR] Access denied - Email mismatch: {user_profile['email']} vs {user_email}")
            await websocket.close(code=1008, reason="Access denied")
            return
        
        print("[DEBUG] Access granted - setting up connection manager")
        
        # Set up the connection in the manager
        manager.active_connections[connection_id] = websocket
        manager.user_sessions[connection_id] = {
            "scan_id": scan_id,
            "user_email": user_email,
            "connected_at": datetime.now(),
            "is_processing": False,
            "is_streaming": False
        }
        
        manager.transcribers[connection_id] = StreamingTranscriber(scan_id, user_email, manager)
        
        logger.info(f"WebSocket connected: {connection_id}")
        
        # Send connection established message
        await manager.send_message(scan_id, user_email, {
            "type": "connection_established",
            "message": "Connected to real-time streaming chat",
            "scan_id": scan_id,
            "capabilities": ["text", "audio_streaming", "real_time_transcription"],
            "timestamp": datetime.now().isoformat()
        })
        
        print(f"[DEBUG] WebSocket connection established for {user_email}_{scan_id}")
        
        # Main message loop with proper disconnect handling
        while True:
            try:
                # Check if connection is still active before trying to receive
                if connection_id not in manager.active_connections:
                    print(f"[DEBUG] Connection {connection_id} no longer active, breaking loop")
                    break
                
                # Check WebSocket state before trying to receive
                if websocket.client_state.name == "DISCONNECTED":
                    print(f"[DEBUG] WebSocket is disconnected, breaking loop")
                    break
                
                # Use receive_text() and catch WebSocketDisconnect specifically
                try:
                    data = await websocket.receive_text()
                except WebSocketDisconnect:
                    print(f"[DEBUG] WebSocket disconnected normally")
                    break
                except Exception as e:
                    print(f"[ERROR] Error receiving message: {e}")
                    break
                
                # Process the message
                try:
                    message_data = json.loads(data)
                    message_type = message_data.get("type")
                    print(f"[DEBUG] Received message type: {message_type}")
                    
                    if message_type == "start_streaming":
                        manager.set_streaming(scan_id, user_email, True)
                        await manager.send_message(scan_id, user_email, {
                            "type": "streaming_started",
                            "message": "Ready to receive audio stream",
                            "timestamp": datetime.now().isoformat()
                        })
                        
                    elif message_type == "audio_chunk":
                        if not manager.is_streaming(scan_id, user_email):
                            continue
                        
                        audio_base64 = message_data.get("audio_data")
                        if audio_base64:
                            try:
                                audio_bytes = base64.b64decode(audio_base64)
                                transcriber = manager.get_transcriber(scan_id, user_email)
                                if transcriber:
                                    transcriber.add_audio_chunk(audio_bytes)
                            except Exception as e:
                                logger.error(f"Error processing audio chunk: {e}")
                                
                    elif message_type == "stop_streaming":
                        manager.set_streaming(scan_id, user_email, False)
                        transcriber = manager.get_transcriber(scan_id, user_email)
                        if transcriber and transcriber.audio_buffer.tell() > 0:
                            audio_data = transcriber.audio_buffer.getvalue()
                            asyncio.create_task(transcriber._transcribe_and_respond(audio_data))
                            transcriber.audio_buffer = io.BytesIO()
                            transcriber.is_recording = False

                        await manager.send_message(scan_id, user_email, {
                            "type": "streaming_stopped",
                            "message": "Audio streaming stopped",
                            "timestamp": datetime.now().isoformat()
                        })
                        
                    elif message_type == "text":
                        if manager.is_processing(scan_id, user_email):
                            await manager.send_message(scan_id, user_email, {
                                "type": "error",
                                "message": "Already processing a request. Please wait."
                            })
                            continue
                        
                        manager.set_processing(scan_id, user_email, True)
                        try:
                            await process_chat_message(scan_id, user_email, message_data, db)
                        finally:
                            manager.set_processing(scan_id, user_email, False)
                            
                    elif message_type == "audio":
                        if manager.is_processing(scan_id, user_email):
                            await manager.send_message(scan_id, user_email, {
                                "type": "error",
                                "message": "Already processing a request. Please wait."
                            })
                            continue
                        
                        manager.set_processing(scan_id, user_email, True)
                        try:
                            await process_chat_message(scan_id, user_email, message_data, db)
                        finally:
                            manager.set_processing(scan_id, user_email, False)
                    
                    else:
                        await manager.send_message(scan_id, user_email, {
                            "type": "error",
                            "message": f"Unknown message type: {message_type}"
                        })
                        
                except json.JSONDecodeError as e:
                    print(f"[ERROR] JSON decode error: {e}")
                    await manager.send_message(scan_id, user_email, {
                        "type": "error",
                        "message": "Invalid JSON format"
                    })
                except Exception as e:
                    print(f"[ERROR] Error processing message: {e}")
                    print(f"[ERROR] Traceback: {traceback.format_exc()}")
                    await manager.send_message(scan_id, user_email, {
                        "type": "error",
                        "message": f"Error processing message: {str(e)}"
                    })
                    
            except Exception as e:
                print(f"[ERROR] Unexpected error in message loop: {e}")
                print(f"[ERROR] Traceback: {traceback.format_exc()}")
                break
                
    except WebSocketDisconnect:
        print(f"[DEBUG] WebSocket disconnected for {connection_id}")
    except Exception as e:
        print(f"[ERROR] WebSocket error: {e}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
    finally:
        # Clean up resources
        if user_email and connection_id:
            manager.disconnect(scan_id, user_email)
            print(f"[DEBUG] Cleaned up connection for {connection_id}")
        
        # Don't try to close the websocket if it's already disconnected
        try:
            if websocket.client_state.name != "DISCONNECTED":
                await websocket.close()
                print(f"[DEBUG] Closed websocket connection")
        except Exception as e:
            print(f"[DEBUG] Error closing websocket (likely already closed): {e}")

async def process_chat_message(scan_id: str, user_email: str, message_data: dict, db):
    try:
        message_type = message_data.get("type")
        user_message = None
        
        await manager.send_message(scan_id, user_email, {
            "type": "processing",
            "message": "Processing your message..."
        })
        
        if message_type == "text":
            user_message = message_data.get("message", "").strip()
            if not user_message:
                await manager.send_message(scan_id, user_email, {
                    "type": "error",
                    "message": "Empty text message received"
                })
                return
                
        elif message_type == "audio":
            audio_base64 = message_data.get("audio_data")
            if not audio_base64:
                await manager.send_message(scan_id, user_email, {
                    "type": "error",
                    "message": "No audio data received"
                })
                return
            
            try:
                audio_bytes = base64.b64decode(audio_base64)
                
                await manager.send_message(scan_id, user_email, {
                    "type": "transcribing",
                    "message": "Converting speech to text..."
                })
                
                user_message = speech_to_text_stream(audio_bytes)
                
                if not user_message:
                    await manager.send_message(scan_id, user_email, {
                        "type": "error",
                        "message": "Failed to convert speech to text"
                    })
                    return
                
                await manager.send_message(scan_id, user_email, {
                    "type": "transcription",
                    "message": user_message
                })
                
            except Exception as e:
                await manager.send_message(scan_id, user_email, {
                    "type": "error",
                    "message": f"Error processing audio: {str(e)}"
                })
                return
        else:
            await manager.send_message(scan_id, user_email, {
                "type": "error",
                "message": "Invalid message type. Use 'text' or 'audio'"
            })
            return
        
        db.add_chat_message(scan_id, "user", user_message)
        
        await manager.send_message(scan_id, user_email, {
            "type": "generating",
            "message": "Generating response..."
        })
        
        chat_history = db.get_chat_history(scan_id)
        
        filtered_history = []
        original_analysis = None
        
        for msg in chat_history:
            if msg["role"] == "system":
                continue
            elif msg["role"] == "assistant" and msg["message"].startswith("{"):
                original_analysis = msg["message"]
                continue
            else:
                filtered_history.append({
                    "role": msg["role"],
                    "content": msg["message"]
                })
        
        chat_system_message = {
            "role": "system",
            "content": (
                "You are NuFit — a fun, stylish fashion AI assistant. "
                "You are now in REAL-TIME CHAT MODE. "
                "IMPORTANT: Do NOT return JSON responses. Respond naturally in conversation. "
                "Keep responses concise (2-3 sentences max) for real-time chat. "
                "Speak like a cool, supportive friend who knows fashion. "
                "Be helpful, encouraging, and give practical fashion advice. "
                "You previously analyzed this user's outfit and gave them a score. "
                "Reference that analysis when relevant, but respond conversationally. "
                "If user asks anything unrelated to fashion or styling tips, tell user to stick to the topic. "
                "For real-time chat, keep responses short and engaging."
            )
        }
        
        gpt_messages = [chat_system_message]
        
        if original_analysis:
            try:
                parsed_analysis = json.loads(original_analysis.strip())
                context_message = {
                    "role": "assistant",
                    "content": f"I previously analyzed your outfit and gave you a {parsed_analysis.get('score', 'N/A')} score. {parsed_analysis.get('stylist_says', '')}"
                }
                gpt_messages.append(context_message)
            except:
                gpt_messages.append({
                    "role": "assistant", 
                    "content": "I previously analyzed your outfit and provided feedback."
                })
        
        gpt_messages.extend(filtered_history)
        
        reply = chat_with_gpt(gpt_messages, max_tokens=150)
        
        if not reply:
            await manager.send_message(scan_id, user_email, {
                "type": "error",
                "message": "Failed to generate response"
            })
            return
        
        db.add_chat_message(scan_id, "assistant", reply)
        
        await manager.send_message(scan_id, user_email, {
            "type": "response",
            "message": reply,
            "timestamp": datetime.now().isoformat()
        })
        
        asyncio.create_task(generate_and_send_audio(scan_id, user_email, reply))
        
    except Exception as e:
        logger.error(f"Error processing chat message: {e}")
        await manager.send_message(scan_id, user_email, {
            "type": "error",
            "message": f"An error occurred: {str(e)}"
        })

async def generate_and_send_audio(scan_id: str, user_email: str, text: str):
    try:
        await manager.send_message(scan_id, user_email, {
            "type": "generating_audio",
            "message": "Generating audio response..."
        })
        
        audio_data = generate_response_audio_base64(text, scan_id, "realtime_chat")
        
        if audio_data:
            await manager.send_message(scan_id, user_email, {
                "type": "audio_response",
                "audio_base64": audio_data["audio_base64"],
                "audio_format": audio_data["audio_format"],
                "filename": audio_data["filename"],
                "text": text,
                "timestamp": datetime.now().isoformat()
            })
        else:
            await manager.send_message(scan_id, user_email, {
                "type": "audio_error",
                "message": "Failed to generate audio response"
            })
            
    except Exception as e:
        logger.error(f"Error generating audio: {e}")
        await manager.send_message(scan_id, user_email, {
            "type": "audio_error",
            "message": f"Audio generation failed: {str(e)}"
        })

# Add these endpoints to your main FastAPI app
@app.get("/ws/chat/status/{scan_id}")
async def get_chat_status(scan_id: str, current_user: dict = Depends(get_authenticated_user)):
    """Get current chat status for a scan"""
    user_email = current_user["email"]
    connection_id = f"{user_email}_{scan_id}"
    
    is_connected = connection_id in manager.active_connections
    is_processing = manager.is_processing(scan_id, user_email) if is_connected else False
    is_streaming = manager.is_streaming(scan_id, user_email) if is_connected else False
    
    return {
        "scan_id": scan_id,
        "is_connected": is_connected,
        "is_processing": is_processing,
        "is_streaming": is_streaming,
        "active_connections": len(manager.active_connections)
    }

@app.post("/ws/chat/disconnect/{scan_id}")
async def force_disconnect_chat(scan_id: str, current_user: dict = Depends(get_authenticated_user)):
    """Force disconnect a WebSocket connection"""
    user_email = current_user["email"]
    connection_id = f"{user_email}_{scan_id}"
    
    if connection_id in manager.active_connections:
        websocket = manager.active_connections[connection_id]
        await websocket.close(code=1000, reason="Force disconnect")
        manager.disconnect(scan_id, user_email)
        return {"message": "Connection closed"}
    else:
        return {"message": "No active connection found"}












# Previous chat endpoint

@app.post("/chat/")
async def chat_endpoint(
    scan_id: str = Form(...),
    message: str = Form(None),
    audio_file: UploadFile = File(None),
    current_user: dict = Depends(get_authenticated_user)
):
    try:
        if not scan_id:
            return JSONResponse(
                status_code=400, 
                content={"error": "Missing required field: scan_id"}
            )

        # Check if we have either message or audio_file
        if not message and not audio_file:
            return JSONResponse(
                status_code=400, 
                content={"error": "Either message or audio_file must be provided"}
            )

        user_message = None

        # If audio file is provided, convert speech to text
        if audio_file:
            try:
                # Read audio file content
                audio_content = await audio_file.read()
                
                # Convert speech to text using ElevenLabs
                user_message = speech_to_text(audio_content)
                
                if not user_message:
                    return JSONResponse(
                        status_code=400,
                        content={"error": "Failed to convert speech to text"}
                    )
                    
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": f"Error processing audio file: {str(e)}"}
                )
        else:
            # Use the provided text message
            user_message = message

        if not user_message or not user_message.strip():
            return JSONResponse(
                status_code=400,
                content={"error": "No valid message content found"}
            )

        # Get user_id from email (since we need the UUID user_id for scans table)
        user_email = current_user["email"]
        
        scan = db.get_scan(scan_id)
        if not scan:
            return JSONResponse(status_code=404, content={"error": "Scan not found"})

        # Verify the scan belongs to a user with this email
        user_profile = db.get_user(scan["user_id"])
        if not user_profile or user_profile["email"] != user_email:
            return JSONResponse(status_code=403, content={"error": "Access denied"})

        # Store user message in chat history
        db.add_chat_message(scan_id, "user", user_message)

        # Retrieve all previous messages for this scan
        chat_history = db.get_chat_history(scan_id)
        
        # Filter out the original system message and create a new chat-focused one
        filtered_history = []
        original_analysis = None
        
        for msg in chat_history:
            if msg["role"] == "system":
                continue  # Skip system messages from database
            elif msg["role"] == "assistant" and msg["message"].startswith("{"):
                # This is likely the original JSON analysis
                original_analysis = msg["message"]
                continue  # Don't include the JSON in chat history
            else:
                filtered_history.append({
                    "role": msg["role"],
                    "content": msg["message"]
                })

        # Create a new system message specifically for chat mode
        chat_system_message = {
            "role": "system",
            "content": (
                "You are NuFit — a fun, stylish fashion AI assistant who always responds in English, even if the user speaks another language."
                "You are now in CHAT MODE, not analysis mode. "
                "IMPORTANT: Do NOT return JSON responses. Respond naturally in conversation. "
                "Speak like a cool, supportive friend who knows fashion. "
                "Be helpful, encouraging, and give practical fashion advice. "
                "You previously analyzed this user's outfit and gave them a score. "
                "Reference that analysis when relevant, but respond conversationally. "
                "Answer their questions directly and naturally. "
                "If user asks anything unrelated to fashion or styling tips, tell user to stick to the topic"
            )
        }

        # Build the message list for GPT
        gpt_messages = [chat_system_message]
        
        # Add a context message about the original analysis if we have it
        if original_analysis:
            try:
                parsed_analysis = json.loads(original_analysis.strip())
                context_message = {
                    "role": "assistant",
                    "content": f"I previously analyzed your outfit and gave you a {parsed_analysis.get('score', 'N/A')} score. {parsed_analysis.get('stylist_says', '')}"
                }
                gpt_messages.append(context_message)
            except:
                # If parsing fails, just add a generic context
                gpt_messages.append({
                    "role": "assistant", 
                    "content": "I previously analyzed your outfit and provided feedback."
                })
        
        # Add the filtered chat history
        gpt_messages.extend(filtered_history)

        # Query GPT with the properly formatted history
        reply = chat_with_gpt(gpt_messages)

        if reply:
            # Store assistant's reply
            db.add_chat_message(scan_id, "assistant", reply)
            
            # Generate audio for the chat response (base64)
            audio_data = generate_response_audio_base64(reply, scan_id, "chat")
            
            response_data = {
                "reply": reply,
                "transcribed_message": user_message if audio_file else None
            }
            
            # Add audio data if generation was successful
            if audio_data:
                response_data.update({
                    "audio_base64": audio_data["audio_base64"],
                    "audio_format": audio_data["audio_format"],
                    "audio_filename": audio_data["filename"]
                })
            
            return response_data
        else:
            return JSONResponse(status_code=500, content={"error": "No reply from GPT."})

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# Updated analyze-outfit endpoint
# @app.post("/analyze-outfit/")
# async def analyze_outfit(
#     video: UploadFile = File(...),
#     current_user: dict = Depends(get_authenticated_user)
# ):
#     try:
#         # Get or create user profile for outfit analysis
#         user_email = current_user["email"]
        
#         # Use the helper function to get or create user profile
#         user_id = get_or_create_user_profile(db, user_email)
        
#         if not user_id:
#             return JSONResponse(
#                 status_code=500, 
#                 content={"error": "Failed to create or find user profile"}
#             )

#         # Generate unique scan ID
#         scan_id = str(uuid.uuid4())
        
#         # Save video to disk
#         video_filename = f"{scan_id}_{video.filename}"
#         video_path = os.path.join(UPLOAD_DIR, video_filename)
#         with open(video_path, "wb") as buffer:
#             shutil.copyfileobj(video.file, buffer)

#         # Create scan-specific frame directory
#         scan_frame_dir = os.path.join(FRAME_DIR, scan_id)
#         os.makedirs(scan_frame_dir, exist_ok=True)

#         # Extract frames
#         extract_frames(video_path, scan_frame_dir)

#         # Load image messages (max 5)
#         image_messages = load_image_messages(scan_frame_dir)
#         if not image_messages:
#             return JSONResponse(status_code=400, content={"error": "No frames extracted."})

#         # Get frame paths for database storage
#         frame_paths = []
#         image_extensions = (".jpg", ".jpeg", ".png")
#         for filename in sorted(os.listdir(scan_frame_dir))[:5]:
#             if filename.lower().endswith(image_extensions):
#                 frame_paths.append(os.path.join(scan_frame_dir, filename))

#         # Updated system message to handle both analysis and chat
#         system_message = {
#             "role": "system",
#             "content": (
#                 "You are NuFit — a fun, stylish fashion AI that gives punchy feedback and outfit ratings.\n"
#                 "Speak like a cool cousin — fun, honest, and baby-simple.\n\n"

#                 "INITIAL OUTFIT ANALYSIS MODE:\n"
#                 "When analyzing outfit images, check how many people are present:\n\n"
                
#                 "FOR SINGLE PERSON:\n"
#                 "Return a JSON object WITHOUT position labels:\n"
#                 "{\n"
#                 "  \"score\": \"89/100\",\n"
#                 "  \"fit_line\": \"Cozy vibes with a chic twist.\",\n"
#                 "  \"stylist_says\": \"Loving the comfy joggers paired with a sleek crop top—perfect balance!\",\n"
#                 "  \"what_went_wrong\": \"Could use some standout accessories or shoes to elevate the look.\"\n"
#                 "}\n\n"
                
#                 "FOR MULTIPLE PEOPLE (2-3 people):\n"
#                 "Label them as 'Left', 'Middle', and 'Right' based on their position in the image.\n"
#                 "Return a JSON object WITH position labels:\n"
#                 "{\n"
#                 "  \"score\": \"Left: 89/100, Middle: 78/100, Right: 82/100\",\n"
#                 "  \"fit_line\": \"Left: ..., Middle: ..., Right: ...\",\n"
#                 "  \"stylist_says\": \"Left: ..., Middle: ..., Right: ...\",\n"
#                 "  \"what_went_wrong\": \"Left: ..., Middle: ..., Right: ...\"\n"
#                 "}\n\n"
                
#                 "All values must be in one JSON object only — no nested or separate person objects.\n"
                
#                 "Scoring Rules:\n"
#                 "• Matching tones: +10\n"
#                 "• Contradicting styles: -10\n"
#                 "• >3 bold colors: -5\n"
#                 "• No shoes: -15\n"
#                 "• Slides/formals mismatch: -20\n"
#                 "• Matching top & bottom: +15\n"
#                 "• Shoes match outfit: +10\n"
#                 "• Fits the event: +10\n"
#                 "• Clashing colors (e.g. red+orange): -10\n\n"
                
#                 "Adjust with fashion sense if rules are broken but the outfit still slays or follows rules but looks boring.\n\n"
                
#                 "CHAT MODE:\n"
#                 "After the initial analysis, respond naturally in conversation. Keep your cool cousin personality:\n"
#                 "• Give styling tips and advice\n"
#                 "• Answer questions about fashion, colors, trends\n"
#                 "• Suggest outfit improvements or alternatives\n"
#                 "• Be encouraging but honest\n"
#                 "• Use casual, friendly language\n"
#                 "• Reference their previous outfit analysis when relevant\n"
#                 "If user asks anything unrelated to fashion or styling tips, tell user to stick to the topic\n\n"
                
#                 "IMPORTANT: For initial outfit analysis, return ONLY the JSON object (no markdown, no code blocks). For follow-up chat, respond naturally as NuFit."
#             )
#         }

#         user_text_message = {
#             "role": "user",
#             "content": "Please analyze the following outfit images using NuFit style rules and give me my FitScore and tips!"
#         }

#         user_image_message = {
#             "role": "user",
#             "content": [
#                 {
#                     "type": "text",
#                     "text": (
#                         "Assume the person's gender presentation from the image. Use NuFit JSON format for analysis: "
#                         "score, fit_line, stylist_says, what_went_wrong. Keep it short and voice-friendly! "
#                         "Return only valid JSON, no markdown formatting."
#                     )
#                 }
#             ] + image_messages
#         }

#         # Compose message list and get response
#         messages = [system_message, user_text_message, user_image_message]
#         reply = chat_with_gpt(messages)

#         if not reply:
#             return JSONResponse(status_code=500, content={"error": "Failed to get outfit analysis"})

#         # Updated main.py endpoint section (replace the JSON parsing section)

#         # Parse JSON response from GPT
#         import re

#         try:
#             # Clean the response by removing markdown code blocks if present
#             cleaned_reply = reply.strip()
#             if cleaned_reply.startswith('```json'):
#                 cleaned_reply = cleaned_reply[7:]  # Remove ```json
#             if cleaned_reply.endswith('```'):
#                 cleaned_reply = cleaned_reply[:-3]  # Remove ```
#             cleaned_reply = cleaned_reply.strip()
            
#             # Parse JSON
#             parsed_response = json.loads(cleaned_reply)
            
#             # Extract individual components
#             score = parsed_response.get("score", "N/A")
#             fit_line = parsed_response.get("fit_line", "")
#             stylist_says = parsed_response.get("stylist_says", "")
#             what_went_wrong = parsed_response.get("what_went_wrong", "")
            
#             # Extract all numeric scores
#             score_matches = re.findall(r'(\d+)/100', score)
#             if score_matches:
#                 individual_scores = [int(match) for match in score_matches]
#             else:
#                 individual_scores = []
            
#         except (json.JSONDecodeError, KeyError) as e:
#             print(f"JSON parsing error: {e}")
#             print(f"Raw reply: {reply}")
            
#             # Fallback: extract scores from raw reply
#             score_matches = re.findall(r'(\d+)/100', reply)
#             if score_matches:
#                 individual_scores = [int(match) for match in score_matches]
#             else:
#                 individual_scores = []
            
#             # Return in original format as fallback
#             parsed_response = {
#                 "score": f"{individual_scores[0]}/100" if individual_scores else "N/A",
#                 "fit_line": "Analysis complete!",
#                 "stylist_says": reply[:100] + "..." if len(reply) > 100 else reply,
#                 "what_went_wrong": "Could not parse detailed feedback"
#             }
#             score = parsed_response["score"]
#             fit_line = parsed_response["fit_line"]
#             stylist_says = parsed_response["stylist_says"]
#             what_went_wrong = parsed_response["what_went_wrong"]

#         # Create scan record in database with individual scores
#         scan_success = db.create_scan(
#             scan_id=scan_id,
#             user_id=user_id,
#             video_path=video_path,
#             image_paths=frame_paths,
#             individual_scores=individual_scores,  # Pass list of individual scores
#             feedback=reply
#         )

#         if not scan_success:
#             return JSONResponse(status_code=500, content={"error": "Failed to save scan data"})

#         # Store initial chat messages with updated system message for future chats
#         chat_system_message = (
#             "You are NuFit — a fun, stylish fashion AI that gives punchy feedback and outfit ratings. "
#             "You previously analyzed this user's outfit. Continue the conversation naturally, "
#             "giving styling tips, answering fashion questions, and being encouraging but honest."
#         )

#         db.add_chat_message(scan_id, "system", chat_system_message)
#         db.add_chat_message(scan_id, "user", user_text_message["content"])
#         db.add_chat_message(scan_id, "user", "Analyze uploaded outfit images")
#         db.add_chat_message(scan_id, "assistant", reply)

#         # Generate audio for the analysis response (base64)
#         audio_data = generate_response_audio_base64(reply, scan_id, "analysis")

#         # Build response data
#         response_data = {
#             "scan_id": scan_id,
#             "score": score,
#             "fit_line": fit_line,
#             "stylist_says": stylist_says,
#             "what_went_wrong": what_went_wrong,
#             "individual_scores": individual_scores,  # List of all individual scores
#             "total_people": len(individual_scores) if individual_scores else 1,
#             "user_id": user_id
#         }

#         # Add audio data if generation was successful
#         if audio_data:
#             response_data.update({
#                 "audio_base64": audio_data["audio_base64"],
#                 "audio_format": audio_data["audio_format"],
#                 "audio_filename": audio_data["filename"]
#             })

#         return response_data


import asyncio
from concurrent.futures import ThreadPoolExecutor
import cv2
import base64
import os
import json
import re
import uuid
import shutil

# Add this helper function for CPU-intensive tasks
async def run_in_thread(func, *args, **kwargs):
    """Run CPU-intensive function in thread pool"""
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        return await loop.run_in_executor(executor, func, *args, **kwargs)

# Optimized frame extraction function
def extract_frames_to_base64(video_path: str, exclude_start: int = 4, exclude_end: int = 7, max_frames: int = 6) -> tuple:
    """Extract frames from video and return as base64 encoded messages directly"""
    image_messages = []
    frame_paths = []  # For database storage
    
    try:
        cap = cv2.VideoCapture(video_path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        if fps <= 0 or total_frames <= 0:
            cap.release()
            return image_messages, frame_paths
        
        # Calculate frame indices to exclude
        exclude_start_frame = int(exclude_start * fps)
        exclude_end_frame = int(exclude_end * fps)
        
        # Get frames to extract (excluding the specified range)
        frame_indices = []
        for i in range(0, total_frames):
            if i < exclude_start_frame or i > exclude_end_frame:
                frame_indices.append(i)
        
        # Limit to max_frames
        if len(frame_indices) > max_frames:
            # Distribute frames evenly
            step = len(frame_indices) // max_frames
            frame_indices = frame_indices[::step][:max_frames]
        
        # Extract frames
        for idx, frame_idx in enumerate(frame_indices):
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
            ret, frame = cap.read()
            
            if ret:
                # Encode frame directly to base64
                _, buffer = cv2.imencode('.jpg', frame)
                frame_base64 = base64.b64encode(buffer).decode('utf-8')
                
                image_messages.append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/jpeg;base64,{frame_base64}"
                    }
                })
                
                # Create frame path for database (these won't be written to disk)
                frame_paths.append(f"frame_{idx+1:03d}.jpg")
        
        cap.release()
        
    except Exception as e:
        print(f"Error extracting frames: {e}")
    
    return image_messages, frame_paths


import asyncio
import json
import uuid
import os
import shutil
import re
import base64
import traceback
import random
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import JSONResponse
import logging

# Import your existing modules
from utils.voiceagent import generate_audio_stream, OpenAITTSStreamer
from utils.key_func import verify_token, get_current_user_email  # Add this import
from database import DatabaseManager  # Add this import
# Import your database and utility functions
# from your_db_module import get_or_create_user_profile, create_scan, add_chat_message
# from your_utils import extract_frames, load_image_messages, chat_with_gpt

logger = logging.getLogger(__name__)

class WebSocketAnalyzeOutfit:
    def __init__(self, db, upload_dir: str, frame_dir: str):
        self.db = db
        self.upload_dir = upload_dir
        self.frame_dir = frame_dir
        self.tts_streamer = OpenAITTSStreamer()
    
    async def authenticate_user(self, token: str) -> Optional[Dict[str, Any]]:
        """Authenticate user using token from URL"""
        try:
            # Use the existing authentication logic from authmiddleware.py
            payload = verify_token(token)
            
            if not payload:
                logger.warning(f"Token verification failed for token: {token[:10]}...")
                return None
            
            email = payload.get("sub")
            if not email:
                logger.warning(f"No email found in token payload: {token[:10]}...")
                return None
            
            # Check if user exists in database
            user = self.db.get_auth_user_by_email(email)
            if not user:
                logger.warning(f"User not found in database: {email}")
                return None
            
            # Check MFA if required
            if payload.get("mfa_required") and not payload.get("mfa_verified"):
                logger.warning(f"MFA verification required for user: {email}")
                return None
            
            return user
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
    
    async def handle_analyze_outfit(self, websocket: WebSocket, data: Dict[str, Any], user_data: Dict[str, Any]):
        """Handle analyze outfit request via WebSocket with streaming audio"""
        try:
            # Extract data from WebSocket message
            scan_id = data.get("scan_id", str(uuid.uuid4()))
            user_email = user_data.get("email")  # Get email from authenticated user data
            input_type = data.get("input_type")  # "video" or "photo"
            file_data = data.get("file_data")  # base64 encoded file data
            filename = data.get("filename")
            
            # Validate input
            if not user_email:
                await self._send_error(websocket, "User email not found in authentication data")
                return
            
            if not input_type or input_type not in ["video", "photo"]:
                await self._send_error(websocket, "Invalid input type. Must be 'video' or 'photo'")
                return
            
            if not file_data or not filename:
                await self._send_error(websocket, "File data and filename are required")
                return
            
            # Send processing status
            await self._send_status(websocket, "processing", "Processing your outfit analysis...")
            
            # Get or create user profile
            user_id = get_or_create_user_profile(self.db, user_email)
            if not user_id:
                await self._send_error(websocket, "Failed to create or find user profile")
                return
            
            # Decode and save file
            try:
                file_bytes = base64.b64decode(file_data)
            except Exception as e:
                await self._send_error(websocket, f"Invalid file data: {str(e)}")
                return
            
            # Create scan-specific frame directory
            scan_frame_dir = os.path.join(self.frame_dir, scan_id)
            os.makedirs(scan_frame_dir, exist_ok=True)
            
            # Handle video or photo processing
            if input_type == "video":
                file_path = await self._process_video(file_bytes, filename, scan_id, scan_frame_dir)
            else:  # photo
                file_path = await self._process_photo(file_bytes, filename, scan_frame_dir)
            
            # Load image messages
            image_messages = load_image_messages(scan_frame_dir)
            if not image_messages:
                await self._send_error(websocket, "No valid images found for analysis")
                return
            
            # Get frame paths for database
            frame_paths = self._get_frame_paths(scan_frame_dir, input_type)
            
            # Send analysis status
            await self._send_status(websocket, "analyzing", "Analyzing your outfit...")
            
            # Perform outfit analysis
            analysis_result = await self._analyze_outfit_with_gpt(image_messages, input_type)
            
            if analysis_result.get("error") == "multiple_people":
                await self._send_error(websocket, analysis_result.get("message", "Multiple people detected"))
                return
            
            # Extract analysis components
            score = analysis_result.get("score", "N/A")
            score_line = analysis_result.get("score_line", "")
            fit_line = analysis_result.get("fit_line", "")
            stylist_says = analysis_result.get("stylist_says", "")
            what_went_wrong = analysis_result.get("what_went_wrong", "")
            greeting = analysis_result.get("greeting", "")  # Extract greeting from LLM response
            
            # Extract numeric score
            individual_scores = self._extract_scores(score, analysis_result.get("raw_reply", ""))
            
            # Save scan to database
            scan_success = self.db.create_scan(
                scan_id=scan_id,
                user_id=user_id,
                video_path=file_path,
                image_paths=frame_paths,
                individual_scores=individual_scores,
                feedback=analysis_result.get("raw_reply", "")
            )
            
            if not scan_success:
                await self._send_error(websocket, "Failed to save scan data")
                return
            
            # Save chat messages
            await self._save_chat_messages(scan_id, analysis_result.get("raw_reply", ""), input_type)
            
            # Send analysis results
            await self._send_analysis_results(websocket, {
                "scan_id": scan_id,
                "score": score,
                "score_line": score_line,
                "fit_line": fit_line,
                "stylist_says": stylist_says,
                "what_went_wrong": what_went_wrong,
                "greeting": greeting,
                "individual_scores": individual_scores,
                "total_people": 1,
                "user_id": user_id,
                "input_type": input_type
            })
            
            # Create user-friendly audio text with greeting
            audio_text = self._create_audio_friendly_text(analysis_result)
            
            # Stream audio response
            await self._stream_audio_response(websocket, audio_text, scan_id)
            
            # Send completion status
            await self._send_status(websocket, "completed", "Analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error in analyze_outfit WebSocket handler: {e}")
            traceback.print_exc()
            await self._send_error(websocket, f"Internal server error: {str(e)}")
    
    def _create_audio_friendly_text(self, analysis_result: Dict[str, Any]) -> str:
        """Create user-friendly text for audio generation with greeting"""
        try:
            # Extract the key components
            greeting = analysis_result.get("greeting", "")
            score_line = analysis_result.get("score_line", "")
            fit_line = analysis_result.get("fit_line", "")
            stylist_says = analysis_result.get("stylist_says", "")
            what_went_wrong = analysis_result.get("what_went_wrong", "")
            
            # Clean up the text by removing JSON formatting characters
            def clean_text(text):
                if not text:
                    return ""
                # Remove common JSON artifacts
                text = text.replace('\\n', ' ').replace('\\"', '"').replace('\\', '')
                text = re.sub(r'[{}"\[\],]', '', text)  # Remove JSON characters
                text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
                return text.strip()
            
            # Clean all components
            clean_greeting = clean_text(greeting)
            clean_score_line = clean_text(score_line)
            clean_fit_line = clean_text(fit_line)
            clean_stylist_says = clean_text(stylist_says)
            clean_what_went_wrong = clean_text(what_went_wrong)
            
            # Construct a natural, conversational response starting with greeting
            audio_parts = []
            
            # Add greeting first
            if clean_greeting:
                audio_parts.append(clean_greeting)
            
            # Add score line instead of basic score
            if clean_score_line:
                audio_parts.append(clean_score_line)
            
            if clean_fit_line:
                audio_parts.append(clean_fit_line)
            
            if clean_stylist_says:
                audio_parts.append(clean_stylist_says)
            
            if clean_what_went_wrong:
                audio_parts.append(f"Here's what could be improved: {clean_what_went_wrong}")
            
            # Join with natural pauses
            audio_text = ". ".join(audio_parts) + "."
            
            # Final cleanup
            audio_text = re.sub(r'\.+', '.', audio_text)  # Remove multiple dots
            audio_text = re.sub(r'\s+', ' ', audio_text)  # Normalize whitespace
            
            return audio_text.strip()
            
        except Exception as e:
            logger.error(f"Error creating audio-friendly text: {e}")
            # Fallback without predefined greeting
            return "Your outfit analysis is complete! Check the results above."
    
    async def _process_video(self, file_bytes: bytes, filename: str, scan_id: str, scan_frame_dir: str) -> str:
        """Process video file and extract frames"""
        # Save video to disk
        video_filename = f"{scan_id}_{filename}"
        video_path = os.path.join(self.upload_dir, video_filename)
        
        with open(video_path, "wb") as f:
            f.write(file_bytes)
        
        # Extract frames excluding 4-7 second range
        actual_frames_dir = extract_frames(video_path, scan_frame_dir, exclude_start=4, exclude_end=7)
        
        # Update scan_frame_dir to point to actual frames directory
        if actual_frames_dir != scan_frame_dir:
            # Move frames to expected directory
            for frame_file in os.listdir(actual_frames_dir):
                shutil.move(
                    os.path.join(actual_frames_dir, frame_file),
                    os.path.join(scan_frame_dir, frame_file)
                )
        
        return video_path
    
    async def _process_photo(self, file_bytes: bytes, filename: str, scan_frame_dir: str) -> str:
        """Process photo file"""
        # Save photo directly to frame directory
        photo_filename = "frame_001.jpg"  # Standardize naming
        photo_path = os.path.join(scan_frame_dir, photo_filename)
        
        with open(photo_path, "wb") as f:
            f.write(file_bytes)
        
        return photo_path
    
    def _get_frame_paths(self, scan_frame_dir: str, input_type: str) -> list:
        """Get frame paths for database storage"""
        frame_paths = []
        image_extensions = (".jpg", ".jpeg", ".png")
        max_frames = 6 if input_type == "video" else 1
        
        for filename in sorted(os.listdir(scan_frame_dir))[:max_frames]:
            if filename.lower().endswith(image_extensions):
                frame_paths.append(os.path.join(scan_frame_dir, filename))
        
        return frame_paths
    
    async def _analyze_outfit_with_gpt(self, image_messages: list, input_type: str) -> Dict[str, Any]:
        """Analyze outfit using GPT with the provided system message"""
        system_message = {
            "role": "system",
            "content": (
                "You are NuFit — the coolest, most stylish, and brutally honest fashion bestie ever. You ALWAYS respond in English, even if the user speaks in another language.\n\n"

                "You talk like you're texting your best friend:\n"
                "• Baby-simple words only\n"
                "• No smart-sounding or teacher-y talk\n"
                "• Use real human slang and texting tone like: 'Ouuu okay!', 'Say less!', 'You wild for this one!', etc.\n"
                "• One sentence at a time. Short. Fun. Human.\n"
                "• Always wait for the user to reply between thoughts\n"
                "• Never give all your thoughts at once\n"
                "• Never sound like a robot, a judge, or a fashion critic\n"
                "• You mix confidence, love, and jokes with honest feedback\n\n"

                "Who You Are:\n"
                "You're NuFit — an AI with 40 years of fashion wisdom.\n"
                "You've styled celebrities, athletes, rappers, influencers — and everyday people too.\n"
                "You know that fashion isn't about rules — it's about *feeling yourself*.\n"
                "You're here to hype the user up, keep it real, and make them feel dope in their own skin.\n\n"

                "INITIAL OUTFIT ANALYSIS MODE:\n"
                "When an outfit scan comes in, act like it just happened LIVE. Always start with a fun greeting like:\n"
                "• 'Ouuu okay! I just caught your upload — I see you just scanned your outfit. Let's get into this one together.'\n"
                "• 'Heyyy! Fresh drop alert — I see you just scanned your fit. I'm ready to check it out with you. Let's see what's cooking.'\n"
                "• 'Ouuu you just uploaded this? I'm on it! Let's break it down together.'\n"
                "• 'Okay okay, new scan just came through! I'm hyped to help you style this one up.'\n"
                "• 'Ohhh you just scanned a new fit? Say less — I'm right here with you. Let's dive in.'\n"
                "Rotate your greetings. Never repeat the same one twice in a row.\n\n"

                "HOW TO ANALYZE:\n"
                "First, figure out how many people are in the image. Focus on the primary subject — usually the one in the foreground or center. A 'person' means someone with a clear face or body shape. Ignore reflections, shadows, posters, mannequins, or people in the background.\n\n"

                "IF MULTIPLE PEOPLE ARE IN THE FOREGROUND:\n"
                "If more than one real person is clearly in front, return exactly this:\n"
                "{\n"
                "  \"error\": \"multiple_people\",\n"
                "  \"message\": \"More than one person detected. Cannot scan the outfit. Please ensure only one person is visible in the video/photo.\"\n"
                "}\n\n"

                "IF ONE PERSON IS CLEARLY PRESENT:\n"
                "If it's a solo selfie or there's one obvious person in front, go ahead with the analysis. If you're not sure (like someone in the background), assume it's the person in the front unless there are clearly two.\n"
                "Return only the JSON in this format:\n"
                "{\n"
                "  \"greeting\": \"Ouuu okay! I just caught your upload — I see you just scanned your outfit. Let's get into this one together.\",\n"
                "  \"score\": \"65/100\",\n"
                "  \"score_line\": \"If I had to rate it… I'd say 65 out of 100.\",\n"
                "  \"fit_line\": \"Bro, this look is giving... laundry day vibes.\",\n"
                "  \"stylist_says\": \"Way too casual for a stylish day out. That oversized tee and those shoes just don't click.\",\n"
                "  \"what_went_wrong\": \"Poor coordination, and the fit looks like it was picked in the dark. Better color harmony and a strong piece (like a jacket or shoes) would help.\"\n"
                "}\n\n"

                "SCORE_LINE EXAMPLES:\n"
                "Use natural, conversational ways to present the score. Examples:\n"
                "• \"If I had to rate it… I'd say 85 out of 100.\"\n"
                "• \"Personally, I'd give this one around a 72.\"\n"
                "• \"For me? This feels like a clean 92 today.\"\n"
                "• \"I'm thinking this hits about 78 out of 100.\"\n"
                "• \"Real talk? This is sitting at like 83 for me.\"\n"
                "It must NEVER just say: \"Your score is 85.\" Always make it conversational and personal.\n\n"

                "SCORING RULES:\n"
                "• Matching tones: +10\n"
                "• Contradicting styles: -10\n"
                "• >3 bold colors: -5\n"
                "• No shoes: -15\n"
                "• Slides/formals mismatch: -20\n"
                "• Matching top & bottom: +15\n"
                "• Shoes match outfit: +10\n"
                "• Fits the event: +10\n"
                "• Clashing colors (e.g., red+orange): -10\n"
                "But if a fit breaks rules and still eats? Give it the credit. And if it follows rules but looks boring? Keep it real.\n\n"

                "SCORE TONE GUIDE:\n"
                "• 85 or higher: Go full hype mode. This outfit is 🔥\n"
                "• 70–84: Be real — call out what's cool and what could glow up\n"
                "• 50–69: Lightly drag them (with love). Keep it fun + helpful.\n"
                "• Below 50: Be funny-brutal — real talk only, but no mean stuff. Be the bestie who says what they need to hear.\n\n"

                "IMPORTANT:\n"
                "For initial analysis, return ONLY the JSON with the greeting and score_line fields included. No markdown. No extra text. Just the JSON like you're texting it to your friend straight up.\n"
            )
        }

        
        user_text_message = {
            "role": "user",
            "content": f"Please analyze the following outfit {input_type} using NuFit style rules and give me my FitScore and tips!"
        }
        
        user_image_message = {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Analyze the outfit in the provided images. First, confirm that only one person is present by focusing on the primary subject (typically in the foreground or center of the image, e.g., the person taking a selfie). A 'person' is a human figure with clear facial features or a distinct body outline. Ignore reflections, shadows, mannequins, posters, or background figures. If more than one distinct human figure is clearly present in the foreground, return the multiple_people error JSON. If only one person is detected or reasonably assumed, analyze their outfit using NuFit JSON format: greeting, score, score_line, fit_line, stylist_says, what_went_wrong. Keep it short, voice-friendly, and return only valid JSON, no markdown formatting."
                    )
                }
            ] + image_messages
        }
        
        # Compose messages and get response
        messages = [system_message, user_text_message, user_image_message]
        reply = chat_with_gpt(messages)
        
        if not reply:
            return {"error": "Failed to get outfit analysis"}
        
        # IMPROVED JSON PARSING
        try:
            # Clean the response more thoroughly
            cleaned_reply = reply.strip()
            
            # Remove markdown code blocks
            if cleaned_reply.startswith('```json'):
                cleaned_reply = cleaned_reply[7:]
            if cleaned_reply.startswith('```'):
                cleaned_reply = cleaned_reply[3:]
            if cleaned_reply.endswith('```'):
                cleaned_reply = cleaned_reply[:-3]
            
            # Remove any leading/trailing text that isn't JSON
            # Look for the first { and last }
            first_brace = cleaned_reply.find('{')
            last_brace = cleaned_reply.rfind('}')
            
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                cleaned_reply = cleaned_reply[first_brace:last_brace + 1]
            
            cleaned_reply = cleaned_reply.strip()
            
            # Parse JSON
            parsed_response = json.loads(cleaned_reply)
            parsed_response["raw_reply"] = reply
            
            return parsed_response
            
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"JSON parsing error: {e}")
            logger.error(f"Raw reply: {reply}")
            
            # Check for multiple people error in raw reply
            if "multiple_people" in reply.lower() or "more than one person" in reply.lower():
                return {
                    "error": "multiple_people",
                    "message": "More than one person detected. Cannot scan the outfit."
                }
            
            # Enhanced fallback parsing using regex
            greeting_match = re.search(r'"greeting":\s*"([^"]+)"', reply)
            score_match = re.search(r'"score":\s*"([^"]+)"', reply)
            score_line_match = re.search(r'"score_line":\s*"([^"]+)"', reply)
            fit_line_match = re.search(r'"fit_line":\s*"([^"]+)"', reply)
            stylist_says_match = re.search(r'"stylist_says":\s*"([^"]+)"', reply)
            what_went_wrong_match = re.search(r'"what_went_wrong":\s*"([^"]+)"', reply)
            
            return {
                "greeting": greeting_match.group(1) if greeting_match else "",
                "score": score_match.group(1) if score_match else "N/A",
                "score_line": score_line_match.group(1) if score_line_match else "Analysis complete!",
                "fit_line": fit_line_match.group(1) if fit_line_match else "Analysis complete!",
                "stylist_says": stylist_says_match.group(1) if stylist_says_match else reply[:100] + "..." if len(reply) > 100 else reply,
                "what_went_wrong": what_went_wrong_match.group(1) if what_went_wrong_match else "Could not parse detailed feedback",
                "raw_reply": reply
            }
    
    def _extract_scores(self, score: str, raw_reply: str) -> list:
        """Extract numeric scores from response"""
        score_matches = re.findall(r'(\d+)/100', score)
        if score_matches:
            return [int(score_matches[0])]
        
        # Try extracting from raw reply
        score_matches = re.findall(r'(\d+)/100', raw_reply)
        if score_matches:
            return [int(score_matches[0])]
        
        return []
    
    async def _save_chat_messages(self, scan_id: str, reply: str, input_type: str):
        """Save chat messages to database"""
        chat_system_message = (
            "You are NuFit — a fun, stylish fashion AI that gives punchy feedback and outfit ratings. "
            "You previously analyzed this user's outfit. Continue the conversation naturally, "
            "giving styling tips, answering fashion questions, and being encouraging but honest."
        )
        
        self.db.add_chat_message(scan_id, "system", chat_system_message)
        self.db.add_chat_message(scan_id, "user", f"Please analyze the following outfit {input_type} using NuFit style rules and give me my FitScore and tips!")
        self.db.add_chat_message(scan_id, "user", f"Analyze uploaded outfit {input_type}")
        self.db.add_chat_message(scan_id, "assistant", reply)
    
    async def _stream_audio_response(self, websocket: WebSocket, text: str, scan_id: str):
        """Stream audio response using OpenAI TTS"""
        try:
            await self._send_status(websocket, "generating_audio", "Generating audio response...")
            
            # Validate text before processing
            if not text or not text.strip():
                logger.warning("Empty text provided for audio generation")
                return
            
            # Log the text being processed for debugging
            logger.info(f"Processing audio for scan_id {scan_id}: {text[:100]}...")
            
            # Stream audio chunks
            async for audio_chunk in generate_audio_stream(text, scan_id):
                await websocket.send_text(json.dumps({
                    "type": "audio_chunk",
                    "data": audio_chunk
                }))
                
                # Small delay to prevent overwhelming the client
                await asyncio.sleep(0.01)
                
        except Exception as e:
            logger.error(f"Error streaming audio: {e}")
            await self._send_error(websocket, f"Audio generation failed: {str(e)}")
    
    async def _send_status(self, websocket: WebSocket, status: str, message: str):
        """Send status update to client"""
        await websocket.send_text(json.dumps({
            "type": "status",
            "status": status,
            "message": message
        }))
    
    async def _send_error(self, websocket: WebSocket, message: str):
        """Send error message to client"""
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": message
        }))
    
    async def _send_analysis_results(self, websocket: WebSocket, results: Dict[str, Any]):
        """Send analysis results to client"""
        await websocket.send_text(json.dumps({
            "type": "analysis_results",
            "data": results
        }))

# WebSocket endpoint implementation with URL token
@app.websocket("/ws/analyze-outfit")
async def websocket_analyze_outfit(websocket: WebSocket, token: str = Query(...)):
    """WebSocket endpoint for outfit analysis with streaming audio and URL token authentication"""
    
    # Initialize analyzer
    analyzer = WebSocketAnalyzeOutfit(db, UPLOAD_DIR, FRAME_DIR)
    
    # Authenticate user using token from URL
    user_data = await analyzer.authenticate_user(token)
    if not user_data:
        await websocket.close(code=4001, reason="Authentication failed")
        return
    
    await websocket.accept()
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle different message types
            if message.get("type") == "analyze_outfit":
                await analyzer.handle_analyze_outfit(websocket, message.get("data", {}), user_data)
            else:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Unknown message type"
                }))
                
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": f"WebSocket error: {str(e)}"
            }))
        except:
            pass  # Connection might be closed

# Alternative: Direct WebSocket handler function with URL token
async def handle_websocket_analyze_outfit(websocket: WebSocket, token: str, db, upload_dir: str, frame_dir: str):
    """Direct WebSocket handler function for outfit analysis with URL token authentication"""
    
    analyzer = WebSocketAnalyzeOutfit(db, upload_dir, frame_dir)
    
    # Authenticate user using token from URL
    user_data = await analyzer.authenticate_user(token)
    if not user_data:
        await websocket.close(code=4001, reason="Authentication failed")
        return
    
    await websocket.accept()
    
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "analyze_outfit":
                await analyzer.handle_analyze_outfit(websocket, message.get("data", {}), user_data)
            else:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Unknown message type"
                }))
                
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": f"WebSocket error: {str(e)}"
            }))
        except:
            pass
        
# # New endpoint to serve audio files
# @app.get("/audio/{filename}")
# async def get_audio_file(filename: str):
#     """Serve audio files"""
#     try:
#         audio_path = os.path.join(AUDIO_DIR, filename)
#         if os.path.exists(audio_path):
#             return FileResponse(
#                 audio_path,
#                 media_type="audio/mpeg",
#                 filename=filename
#             )
#         else:
#             raise HTTPException(status_code=404, detail="Audio file not found")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

@app.get("/user/scans-with-history/")
async def get_user_scans_with_history(current_user: dict = Depends(get_authenticated_user)):
    """Get all scans for the current user along with their chat history"""
    try:
        user_email = current_user["email"]
        print(f"Looking for scans for user: {user_email}")
        
        user_profile = db.get_user_by_email(user_email)
        if not user_profile:
            return JSONResponse(status_code=404, content={"error": "User not found"})

        user_id = user_profile["id"]
        print(f"Found user profile with ID: {user_id}")
        
        # Fetch scans for the user_id
        scans_query = """
            SELECT id, user_id, video_path, image_paths, score, feedback, created_at 
            FROM scans 
            WHERE user_id = %s
            ORDER BY created_at DESC
        """
        try:
            user_scans = []
            cursor = db.connection.cursor()
            cursor.execute(scans_query, (user_id,))
            scan_columns = [desc[0] for desc in cursor.description]
            scan_rows = cursor.fetchall()
            cursor.close()

            for scan_row in scan_rows:
                scan = dict(zip(scan_columns, scan_row))
                print(f"Found scan: {scan['id']}")
                
                # Get chat history
                chat_history = db.get_chat_history(scan["id"])
                print(f"Found {len(chat_history)} chat messages for scan {scan['id']}")
                
                # Debug: Print the structure of the first chat message to see available fields
                if chat_history:
                    print(f"Sample chat message structure: {list(chat_history[0].keys())}")

                # Parse analysis
                analysis_data = {}
                if scan.get("feedback"):
                    try:
                        cleaned_feedback = scan["feedback"].strip()
                        if cleaned_feedback.startswith('```json'):
                            cleaned_feedback = cleaned_feedback[7:]
                        if cleaned_feedback.endswith('```'):
                            cleaned_feedback = cleaned_feedback[:-3]
                        cleaned_feedback = cleaned_feedback.strip()
                        
                        parsed_feedback = json.loads(cleaned_feedback)
                        analysis_data = {
                            "score": parsed_feedback.get("score", f"{scan['score']}/100" if scan['score'] else "N/A"),
                            "fit_line": parsed_feedback.get("fit_line", ""),
                            "stylist_says": parsed_feedback.get("stylist_says", ""),
                            "what_went_wrong": parsed_feedback.get("what_went_wrong", "")
                        }
                    except json.JSONDecodeError:
                        analysis_data = {
                            "score": f"{scan['score']}/100" if scan['score'] else "N/A",
                            "fit_line": "",
                            "stylist_says": scan.get("feedback", ""),
                            "what_went_wrong": ""
                        }

                # Parse image paths
                image_paths = []
                if scan.get("image_paths"):
                    try:
                        image_paths = (
                            json.loads(scan["image_paths"])
                            if isinstance(scan["image_paths"], str)
                            else scan["image_paths"]
                        )
                    except:
                        image_paths = []

                # ENHANCED MESSAGE FILTERING - Replace your existing filtering logic with this
                def should_filter_message(message, role):
                    """
                    Determine if a message should be filtered out
                    Returns True if message should be filtered (removed)
                    """
                    # Filter system messages
                    if role == "system":
                        return True
                    
                    # Filter empty messages
                    if not message.strip():
                        return True
                    
                    # Filter generic/template messages
                    generic_patterns = [
                        "analyze the following outfit images using nufit style rules",
                        "analyze uploaded outfit images",
                        "please analyze the following",
                        "give me my fitscore",
                        # Add more patterns as needed
                    ]
                    
                    message_lower = message.lower()
                    if any(pattern in message_lower for pattern in generic_patterns):
                        return True
                    
                    # Filter messages that are just JSON responses (optional)
                    if message.strip().startswith('{') and message.strip().endswith('}'):
                        try:
                            json.loads(message)
                            return True  # It's a JSON response, filter it out
                        except json.JSONDecodeError:
                            pass  # Not valid JSON, keep it
                    
                    return False

                # Format chat history with enhanced filtering
                formatted_chat_history = []
                seen_messages = set()  # To track duplicate messages

                for msg in chat_history:
                    message_content = msg["message"].strip()
                    
                    # Apply filtering logic
                    if should_filter_message(message_content, msg["role"]):
                        continue
                    
                    # Check for duplicates
                    message_key = f"{msg['role']}:{message_content}"
                    if message_key in seen_messages:
                        continue
                    seen_messages.add(message_key)
                    
                    # Handle different possible timestamp field names
                    timestamp = None
                    for time_field in ['timestamp', 'created_at', 'date_created', 'time']:
                        if time_field in msg and msg[time_field]:
                            timestamp = msg[time_field]
                            break
                    
                    # If no timestamp found, use current time or scan creation time as fallback
                    if not timestamp:
                        timestamp = scan["created_at"]
                    
                    formatted_msg = {
                        "id": msg.get("id", ""),
                        "role": msg["role"],
                        "message": message_content,
                        "timestamp": timestamp
                    }
                    formatted_chat_history.append(formatted_msg)

                # Determine last activity - use the latest timestamp from chat or scan creation
                last_activity = scan["created_at"]  # Default fallback
                if formatted_chat_history:
                    try:
                        # Try to find the most recent timestamp
                        chat_timestamps = [msg["timestamp"] for msg in formatted_chat_history if msg["timestamp"]]
                        if chat_timestamps:
                            last_activity = max(chat_timestamps)
                    except Exception as e:
                        print(f"Error determining last activity: {e}")
                        # Keep the default fallback

                scan_data = {
                    "scan_id": scan["id"],
                    "created_at": scan["created_at"],
                    "numeric_score": scan["score"],
                    "video_path": scan["video_path"],
                    "image_paths": image_paths,
                    "analysis": analysis_data,
                    "chat_history": formatted_chat_history,
                    "total_messages": len(formatted_chat_history),
                    "last_activity": last_activity
                }

                user_scans.append(scan_data)

            # Sort by recent activity (handle potential datetime comparison issues)
            try:
                user_scans.sort(key=lambda x: x["last_activity"], reverse=True)
            except Exception as e:
                print(f"Error sorting scans by last_activity: {e}")
                # Fallback: sort by created_at
                user_scans.sort(key=lambda x: x["created_at"], reverse=True)

            return {
                "user_email": user_email,
                "total_scans": len(user_scans),
                "scans": user_scans
            }

        except Exception as e:
            print(f"Error querying database: {e}")
            import traceback
            traceback.print_exc()
            return JSONResponse(status_code=500, content={"error": f"Database query failed: {str(e)}"})

    except Exception as e:
        print(f"Error getting user scans with history: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})

def get_or_create_user_profile(db, user_email):
    """Get existing user profile or create a new one"""
    try:
        query = "SELECT * FROM users WHERE email = %s"
        cursor = db.connection.cursor()
        cursor.execute(query, (user_email,))
        columns = [desc[0] for desc in cursor.description]
        result = cursor.fetchone()
        cursor.close()

        if result:
            user_profile = dict(zip(columns, result))
            print(f"Found existing user profile: {user_profile['id']}")
            return user_profile["id"]
        else:
            user_id = str(uuid.uuid4())
            success = db.create_user(user_id, user_email)
            if success:
                print(f"Created new user profile: {user_id}")
                return user_id
            else:
                print("Failed to create user profile")
                return None

    except Exception as e:
        print(f"Error in get_or_create_user_profile: {e}")
        return None



@app.get("/user/scans-with-history-optimized/")
async def get_user_scans_with_history_optimized(current_user: dict = Depends(get_authenticated_user)):
    """Optimized version - gets user scans with history using proper user lookup"""
    try:
        user_email = current_user["email"]
        
        # Get user_id from users table by email
        user_profile = db.get_user_by_email(user_email)  # You'll need to implement this
        if not user_profile:
            return {
                "user_email": user_email,
                "total_scans": 0,
                "scans": [],
                "message": "No user profile found"
            }
        
        user_id = user_profile["id"]
        
        # Get all scans for this user
        user_scans_raw = db.get_user_scans(user_id)
        
        user_scans = []
        for scan in user_scans_raw:
            # Get chat history for this scan
            chat_history = db.get_chat_history(scan["id"])
            
            # Parse the original analysis from the feedback
            analysis_data = {}
            if scan.get("feedback"):
                try:
                    parsed_feedback = json.loads(scan["feedback"])
                    analysis_data = {
                        "score": parsed_feedback.get("score", f"{scan['score']}/100" if scan['score'] else "N/A"),
                        "fit_line": parsed_feedback.get("fit_line", ""),
                        "stylist_says": parsed_feedback.get("stylist_says", ""),
                        "what_went_wrong": parsed_feedback.get("what_went_wrong", "")
                    }
                except:
                    analysis_data = {
                        "score": f"{scan['score']}/100" if scan['score'] else "N/A",
                        "fit_line": "",
                        "stylist_says": scan.get("feedback", ""),
                        "what_went_wrong": ""
                    }
            
            # Format the scan data
            scan_data = {
                "scan_id": scan["id"],
                "created_at": scan["created_at"],
                "numeric_score": scan["score"],
                "video_path": scan["video_path"],
                "image_paths": scan.get("image_paths", []),
                "analysis": analysis_data,
                "chat_history": [
                    {
                        "id": msg["id"],
                        "role": msg["role"],
                        "message": msg["message"],
                        "timestamp": msg["timestamp"]
                    }
                    for msg in chat_history
                    if msg["role"] != "system"  # Filter out system messages for cleaner history
                ],
                "total_messages": len([msg for msg in chat_history if msg["role"] != "system"]),
                "last_activity": chat_history[-1]["timestamp"] if chat_history else scan["created_at"]
            }
            
            user_scans.append(scan_data)
        
        # Sort by last activity (most recent first)
        user_scans.sort(key=lambda x: x["last_activity"], reverse=True)
        
        return {
            "user_id": user_id,
            "user_email": user_email,
            "total_scans": len(user_scans),
            "scans": user_scans
        }
        
    except Exception as e:
        print(f"Error getting user scans with history: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/scan/{scan_id}/history/")
async def get_scan_history(
    scan_id: str, 
    current_user: dict = Depends(get_authenticated_user)
):
    try:
        # Verify scan exists and belongs to current user
        scan = db.get_scan(scan_id)
        if not scan:
            return JSONResponse(status_code=404, content={"error": "Scan not found"})

        # Get user profile and verify ownership
        user_profile = db.get_user(scan["user_id"])
        if not user_profile or user_profile["email"] != current_user["email"]:
            return JSONResponse(status_code=403, content={"error": "Access denied"})

        history = db.get_chat_history(scan_id)
        return {"history": history}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# Public routes
# @app.get("/", response_class=HTMLResponse)
# async def serve_frontend(request: Request):
    # return templates.TemplateResponse("index.html", {"request": request})

# Legacy endpoints (for backward compatibility - consider removing these)
@app.post("/create-user/")
async def create_user():
    """Legacy endpoint - consider removing and using signup instead"""
    try:
        user_id = str(uuid.uuid4())
        success = db.create_user(user_id)
        
        if success:
            return {"user_id": user_id}
        else:
            return JSONResponse(status_code=500, content={"error": "Failed to create user"})
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# Pose Guidance

# Add this import at the top of your main.py
import base64
from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from typing import Dict, List, Optional
import json
import asyncio
import base64
from datetime import datetime
import logging
import io
import threading
import queue
import time
from enum import Enum

from utils.key_func import verify_token
from database import DatabaseManager
from gpt import chat_with_gpt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanStage(str, Enum):
    FRONT = "front"
    SIDE = "side"
    BACK = "back"

class ScanGuidanceManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.scan_sessions: Dict[str, Dict] = {}
        
    async def connect(self, websocket: WebSocket, scan_id: str, user_email: str):
        await websocket.accept()
        connection_id = f"{user_email}_{scan_id}"
        self.active_connections[connection_id] = websocket
        self.scan_sessions[connection_id] = {
            "scan_id": scan_id,
            "user_email": user_email,
            "connected_at": datetime.now(),
            "current_stage": ScanStage.FRONT,
            "progress": {
                "front": {"correct_frames": 0, "total_frames": 0, "completed": False},
                "side": {"correct_frames": 0, "total_frames": 0, "completed": False},
                "back": {"correct_frames": 0, "total_frames": 0, "completed": False}
            },
            "total_correct_frames": 0,
            "scan_completed": False,
            "is_processing": False
        }
        
        logger.info(f"Scan guidance WebSocket connected: {connection_id}")

    def disconnect(self, scan_id: str, user_email: str):
        connection_id = f"{user_email}_{scan_id}"
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        if connection_id in self.scan_sessions:
            del self.scan_sessions[connection_id]
        logger.info(f"Scan guidance WebSocket disconnected: {connection_id}")

    async def send_message(self, scan_id: str, user_email: str, message: dict):
        connection_id = f"{user_email}_{scan_id}"
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error sending message to {connection_id}: {e}")
                self.disconnect(scan_id, user_email)

    def get_session(self, scan_id: str, user_email: str) -> Optional[Dict]:
        connection_id = f"{user_email}_{scan_id}"
        return self.scan_sessions.get(connection_id)
    
    def update_progress(self, scan_id: str, user_email: str, stage: str, is_correct: bool):
        connection_id = f"{user_email}_{scan_id}"
        if connection_id not in self.scan_sessions:
            return
        
        session = self.scan_sessions[connection_id]
        progress = session["progress"][stage]
        
        progress["total_frames"] += 1
        
        if is_correct:
            progress["correct_frames"] += 1
            session["total_correct_frames"] += 1
            
            # Check if stage is completed (5 correct frames)
            if progress["correct_frames"] >= 5 and not progress["completed"]:
                progress["completed"] = True
                # Move to next stage
                if stage == "front":
                    session["current_stage"] = ScanStage.SIDE
                elif stage == "side":
                    session["current_stage"] = ScanStage.BACK
                elif stage == "back":
                    session["scan_completed"] = True
        
        return session
    
    def is_scan_completed(self, scan_id: str, user_email: str) -> bool:
        session = self.get_session(scan_id, user_email)
        if not session:
            return False
        
        return (session["progress"]["front"]["completed"] and 
                session["progress"]["side"]["completed"] and 
                session["progress"]["back"]["completed"])

# Create scan guidance manager instance
guidance_manager = ScanGuidanceManager()

class FrameProcessor:
    def __init__(self):
        self.processing_queue = asyncio.Queue()
        
    async def analyze_frame(self, frame_base64: str, current_stage: str) -> Dict:
        """Analyze frame using GPT-4o to determine orientation and correctness"""
        try:
            # Create GPT-4o prompt for frame analysis
            system_message = {
                "role": "system",
                "content": (
                    "You are a fashion AI assistant that analyzes user poses for outfit scanning. "
                    f"The user is currently supposed to be showing their {current_stage} view. "
                    "Analyze the image and determine:\n"
                    "1. What orientation/pose the person is in (front, side, back, or other)\n"
                    "2. Whether this matches the expected orientation\n"
                    "3. Quality of the pose (is the person fully visible, standing straight, etc.)\n"
                    "4. Provide brief guidance for improvement if needed\n\n"
                    "Respond with a JSON object containing:\n"
                    "{\n"
                    '  "detected_orientation": "front|side|back|other",\n'
                    '  "is_correct": true|false,\n'
                    '  "confidence": 0.0-1.0,\n'
                    '  "guidance_message": "Brief instruction for the user",\n'
                    '  "pose_quality": "good|needs_adjustment|poor"\n'
                    "}"
                )
            }
            
            user_message = {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": f"Please analyze this image. The user should be showing their {current_stage} view."
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{frame_base64}"
                        }
                    }
                ]
            }
            
            # Call GPT-4o with vision capabilities
            messages = [system_message, user_message]
            response = chat_with_gpt(messages, max_tokens=200, model="gpt-4o")
            
            if not response:
                return self._default_response("Error analyzing image")
            
            # Try to parse JSON response
            try:
                # Clean response if it has markdown formatting
                clean_response = response.strip()
                if clean_response.startswith("```json"):
                    clean_response = clean_response[7:]
                if clean_response.endswith("```"):
                    clean_response = clean_response[:-3]
                
                result = json.loads(clean_response.strip())
                
                # Validate required fields
                required_fields = ["detected_orientation", "is_correct", "guidance_message"]
                if all(field in result for field in required_fields):
                    return result
                else:
                    return self._default_response("Invalid response format")
                    
            except json.JSONDecodeError:
                # If JSON parsing fails, create a basic response
                return self._parse_text_response(response, current_stage)
                
        except Exception as e:
            logger.error(f"Error analyzing frame: {e}")
            return self._default_response(f"Analysis error: {str(e)}")
    
    def _default_response(self, message: str) -> Dict:
        """Return default response when analysis fails"""
        return {
            "detected_orientation": "unknown",
            "is_correct": False,
            "confidence": 0.0,
            "guidance_message": message,
            "pose_quality": "needs_adjustment"
        }
    
    def _parse_text_response(self, response: str, current_stage: str) -> Dict:
        """Parse text response when JSON parsing fails"""
        response_lower = response.lower()
        
        # Detect orientation
        detected_orientation = "other"
        if "front" in response_lower:
            detected_orientation = "front"
        elif "side" in response_lower:
            detected_orientation = "side"
        elif "back" in response_lower:
            detected_orientation = "back"
        
        # Determine correctness
        is_correct = (detected_orientation == current_stage and 
                     ("good" in response_lower or "correct" in response_lower))
        
        return {
            "detected_orientation": detected_orientation,
            "is_correct": is_correct,
            "confidence": 0.7 if is_correct else 0.3,
            "guidance_message": response[:100] + "..." if len(response) > 100 else response,
            "pose_quality": "good" if is_correct else "needs_adjustment"
        }

# Create frame processor instance
frame_processor = FrameProcessor()

@app.websocket("/ws/scan-guidance/{scan_id}")
async def websocket_scan_guidance_endpoint(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(...)
):
    """WebSocket endpoint for real-time scan guidance with frame analysis"""
    
    # Authenticate user
    current_user = await get_websocket_user(token)
    if not current_user:
        await websocket.close(code=1008, reason="Authentication failed")
        return
    
    user_email = current_user["email"]
    db = DatabaseManager()
    
    # Verify scan access
    scan = db.get_scan(scan_id)
    if not scan:
        await websocket.close(code=1008, reason="Scan not found")
        return
    
    user_profile = db.get_user(scan["user_id"])
    if not user_profile or user_profile["email"] != user_email:
        await websocket.close(code=1008, reason="Access denied")
        return
    
    # Connect to WebSocket
    await guidance_manager.connect(websocket, scan_id, user_email)
    
    # Send initial guidance
    await guidance_manager.send_message(scan_id, user_email, {
        "type": "guidance_started",
        "message": "Scan guidance session started",
        "scan_id": scan_id,
        "current_stage": "front",
        "instructions": "Please stand facing the camera for a front view of your outfit",
        "progress": {
            "front": {"correct_frames": 0, "required_frames": 5, "completed": False},
            "side": {"correct_frames": 0, "required_frames": 5, "completed": False},
            "back": {"correct_frames": 0, "required_frames": 5, "completed": False}
        },
        "timestamp": datetime.now().isoformat()
    })
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            message_type = message_data.get("type")
            session = guidance_manager.get_session(scan_id, user_email)
            
            if not session:
                await guidance_manager.send_message(scan_id, user_email, {
                    "type": "error",
                    "message": "Session not found"
                })
                continue
            
            if message_type == "frame":
                # Handle incoming frame for analysis
                if session["is_processing"]:
                    continue  # Skip if already processing
                
                frame_base64 = message_data.get("frame_data")
                if not frame_base64:
                    await guidance_manager.send_message(scan_id, user_email, {
                        "type": "error",
                        "message": "No frame data received"
                    })
                    continue
                
                # Set processing flag
                session["is_processing"] = True
                
                try:
                    # Analyze frame
                    current_stage = session["current_stage"]
                    analysis_result = await frame_processor.analyze_frame(frame_base64, current_stage)
                    
                    # Update progress
                    is_correct = analysis_result.get("is_correct", False)
                    updated_session = guidance_manager.update_progress(scan_id, user_email, current_stage, is_correct)
                    
                    # Prepare response
                    response_data = {
                        "type": "frame_analysis",
                        "scan_id": scan_id,
                        "current_stage": updated_session["current_stage"],
                        "detected_orientation": analysis_result.get("detected_orientation"),
                        "is_correct": 1 if is_correct else 0,  # Flag as requested
                        "confidence": analysis_result.get("confidence", 0.0),
                        "guidance_message": analysis_result.get("guidance_message"),
                        "pose_quality": analysis_result.get("pose_quality"),
                        "progress": updated_session["progress"],
                        "total_correct_frames": updated_session["total_correct_frames"],
                        "scan_completed": updated_session["scan_completed"],
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    # Check for stage completion
                    if updated_session["progress"][current_stage]["completed"] and current_stage != updated_session["current_stage"]:
                        response_data["stage_completed"] = current_stage
                        response_data["next_stage"] = updated_session["current_stage"]
                        
                        # Add stage-specific instructions
                        stage_instructions = {
                            "side": "Great! Now please turn to show your side profile",
                            "back": "Excellent! Now please turn around to show the back of your outfit"
                        }
                        response_data["next_stage_instructions"] = stage_instructions.get(updated_session["current_stage"], "")
                    
                    # Check for complete scan
                    if guidance_manager.is_scan_completed(scan_id, user_email):
                        response_data["type"] = "scan_complete"
                        response_data["message"] = "Scan completed successfully! Processing your outfit analysis..."
                        
                        # Trigger backend analysis here
                        asyncio.create_task(trigger_outfit_analysis(scan_id, user_email))
                    
                    await guidance_manager.send_message(scan_id, user_email, response_data)
                    
                finally:
                    session["is_processing"] = False
            
            elif message_type == "reset_scan":
                # Reset scan progress
                session["current_stage"] = ScanStage.FRONT
                session["progress"] = {
                    "front": {"correct_frames": 0, "total_frames": 0, "completed": False},
                    "side": {"correct_frames": 0, "total_frames": 0, "completed": False},
                    "back": {"correct_frames": 0, "total_frames": 0, "completed": False}
                }
                session["total_correct_frames"] = 0
                session["scan_completed"] = False
                
                await guidance_manager.send_message(scan_id, user_email, {
                    "type": "scan_reset",
                    "message": "Scan progress reset",
                    "current_stage": "front",
                    "instructions": "Please stand facing the camera for a front view of your outfit",
                    "progress": session["progress"],
                    "timestamp": datetime.now().isoformat()
                })
            
            elif message_type == "get_status":
                # Send current status
                await guidance_manager.send_message(scan_id, user_email, {
                    "type": "status_update",
                    "scan_id": scan_id,
                    "current_stage": session["current_stage"],
                    "progress": session["progress"],
                    "total_correct_frames": session["total_correct_frames"],
                    "scan_completed": session["scan_completed"],
                    "timestamp": datetime.now().isoformat()
                })
            
            else:
                await guidance_manager.send_message(scan_id, user_email, {
                    "type": "error",
                    "message": f"Unknown message type: {message_type}"
                })
                
    except WebSocketDisconnect:
        guidance_manager.disconnect(scan_id, user_email)
    except Exception as e:
        logger.error(f"Scan guidance WebSocket error for {user_email}_{scan_id}: {e}")
        await guidance_manager.send_message(scan_id, user_email, {
            "type": "error",
            "message": f"An error occurred: {str(e)}"
        })
        guidance_manager.disconnect(scan_id, user_email)

async def trigger_outfit_analysis(scan_id: str, user_email: str):
    """Trigger backend outfit analysis when scan is completed"""
    try:
        # Send analysis started notification
        await guidance_manager.send_message(scan_id, user_email, {
            "type": "analysis_started",
            "message": "Starting outfit analysis...",
            "timestamp": datetime.now().isoformat()
        })
        
        # Here you would trigger your existing outfit analysis pipeline
        # This is where you'd send the collected video/frames for processing
        
        # Placeholder for actual analysis call
        # analysis_result = await process_outfit_analysis(scan_id)
        
        # For now, send a completion message
        await guidance_manager.send_message(scan_id, user_email, {
            "type": "analysis_complete",
            "message": "Outfit analysis completed! Check your results.",
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error triggering outfit analysis: {e}")
        await guidance_manager.send_message(scan_id, user_email, {
            "type": "analysis_error",
            "message": f"Analysis failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        })

# Additional REST endpoints for scan guidance management
@app.get("/ws/scan-guidance/status/{scan_id}")
async def get_scan_guidance_status(scan_id: str, current_user: dict = Depends(get_authenticated_user)):
    """Get current scan guidance status"""
    user_email = current_user["email"]
    session = guidance_manager.get_session(scan_id, user_email)
    
    if not session:
        return {
            "scan_id": scan_id,
            "is_connected": False,
            "message": "No active guidance session"
        }
    
    return {
        "scan_id": scan_id,
        "is_connected": True,
        "current_stage": session["current_stage"],
        "progress": session["progress"],
        "total_correct_frames": session["total_correct_frames"],
        "scan_completed": session["scan_completed"],
        "is_processing": session["is_processing"]
    }

@app.post("/ws/scan-guidance/disconnect/{scan_id}")
async def force_disconnect_scan_guidance(scan_id: str, current_user: dict = Depends(get_authenticated_user)):
    """Force disconnect a scan guidance WebSocket connection"""
    user_email = current_user["email"]
    connection_id = f"{user_email}_{scan_id}"
    
    if connection_id in guidance_manager.active_connections:
        websocket = guidance_manager.active_connections[connection_id]
        await websocket.close(code=1000, reason="Force disconnect")
        guidance_manager.disconnect(scan_id, user_email)
        return {"message": "Scan guidance connection closed"}
    else:
        return {"message": "No active scan guidance connection found"}
    

# Maintenance endpoints
@app.post("/admin/cleanup-codes")
async def cleanup_expired_codes():
    """Clean up expired password reset codes"""
    try:
        deleted_count = db.cleanup_expired_codes()
        return {"message": f"Cleaned up {deleted_count} expired codes"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.on_event("startup")
async def startup_event():
    # Initialize database tables
    db.init_db()

    # Clean up expired codes on startup
    try:
        db.cleanup_expired_codes()
    except Exception as e:
        print(f"Warning: Failed to cleanup expired codes on startup: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    # Close database connection
    db.close()