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
from utils.key_func import create_access_token, generate_4_digit_code
from utils.voiceagent import generate_audio
from dotenv import load_dotenv
import base64

load_dotenv()

app = FastAPI()

# Initialize database
db = DatabaseManager()

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="static")  # Assuming HTML is in /static

UPLOAD_DIR = "uploads"
FRAME_DIR = "extracted_frames"
AUDIO_DIR = "audio_files"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(FRAME_DIR, exist_ok=True)
os.makedirs(AUDIO_DIR, exist_ok=True)

# Pydantic models for request/response
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


def generate_response_audio_base64(text_content, scan_id, message_type="analysis"):
    """Generate audio file for response and return base64 encoded data"""
    try:
        print(f"Starting audio generation for {message_type} with scan_id: {scan_id}")
        
        # Extract appropriate text for audio generation
        if message_type == "analysis":
            # For analysis, extract multiple fields from JSON
            audio_text = extract_analysis_fields_from_json(text_content)
        else:
            # For chat, use the full response but limit length
            audio_text = text_content[:200] if len(text_content) > 200 else text_content
        
        print(f"Audio text extracted: {audio_text[:50]}...")
        
        # Generate unique filename
        audio_filename = f"{scan_id}_{message_type}_{uuid.uuid4().hex[:8]}.mp3"
        audio_path = os.path.join(AUDIO_DIR, audio_filename)
        
        print(f"Audio will be saved to: {audio_path}")
        
        # Generate audio using the voice agent
        success = generate_audio(
            text=audio_text,
            output_path=audio_path
        )
        
        print(f"Audio generation result: {success}")
        
        if success and os.path.exists(audio_path):
            file_size = os.path.getsize(audio_path)
            print(f"Audio file created successfully. Size: {file_size} bytes")
            
            # Read the audio file and convert to base64
            try:
                with open(audio_path, "rb") as audio_file:
                    audio_bytes = audio_file.read()
                    audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
                
                # Optionally delete the file after encoding to save space
                # os.remove(audio_path)  # Uncomment if you want to delete after encoding
                
                return {
                    "audio_base64": audio_base64,
                    "audio_format": "audio/mpeg",
                    "filename": audio_filename
                }
                
            except Exception as e:
                print(f"Error reading audio file for base64 conversion: {e}")
                return None
                
        else:
            print(f"Failed to generate audio for {message_type}")
            # Check if file was created but function returned False
            if os.path.exists(audio_path):
                print("Audio file exists but function returned False")
                try:
                    with open(audio_path, "rb") as audio_file:
                        audio_bytes = audio_file.read()
                        audio_base64 = base64.b64encode(audio_bytes).decode('utf-8')
                    
                    return {
                        "audio_base64": audio_base64,
                        "audio_format": "audio/mpeg",
                        "filename": audio_filename
                    }
                except:
                    return None
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
            max_length = 500
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

# Authentication endpoints (keeping existing auth code unchanged)
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

        # Create user profile for outfit analysis
        user_id = str(uuid.uuid4())
        profile_success = db.create_user(user_id, user_data.email)
        
        if not profile_success:
            # Rollback: This is a simplified approach - in production consider transactions
            print(f"Warning: Failed to create user profile for {user_data.email}")

        # Create access token
        access_token = create_access_token(data={"sub": user_data.email})
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create access token"
            )

        # Get user data
        user = db.get_auth_user_by_email(user_data.email)
        
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

# [Keep all existing authentication endpoints unchanged - forgot_password, validate_reset_code, etc.]
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

# Add this import at the top of your main.py
import base64

# Updated chat endpoint
@app.post("/chat/")
async def chat_endpoint(
    message: dict = Body(...),
    current_user: dict = Depends(get_authenticated_user)
):
    try:
        scan_id = message.get("scan_id")
        user_message = message.get("message")
        
        if not scan_id or not user_message:
            return JSONResponse(
                status_code=400, 
                content={"error": "Missing required fields: scan_id or message"}
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
                "You are NuFit — a fun, stylish fashion AI assistant. "
                "You are now in CHAT MODE, not analysis mode. "
                "IMPORTANT: Do NOT return JSON responses. Respond naturally in conversation. "
                "Speak like a cool, supportive friend who knows fashion. "
                "Be helpful, encouraging, and give practical fashion advice. "
                "You previously analyzed this user's outfit and gave them a score. "
                "Reference that analysis when relevant, but respond conversationally. "
                "Answer their questions directly and naturally."
                "If user asks anything unrealted to fashion or styling tips, tell user to stick to the topic"
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
            
            response_data = {"reply": reply}
            
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
@app.post("/analyze-outfit/")
async def analyze_outfit(
    video: UploadFile = File(...),
    current_user: dict = Depends(get_authenticated_user)
):
    try:
        # Get or create user profile for outfit analysis
        user_email = current_user["email"]
        
        # Try to find existing user profile by email
        # This is a simplified approach - you might want to add a proper lookup method
        existing_scans = db.get_user_scans("")  # Get all scans to find user_id
        user_id = None
        
        # Create a new user profile if none exists
        # In a better implementation, you'd create this during signup
        if not user_id:
            user_id = str(uuid.uuid4())
            db.create_user(user_id, user_email)

        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Save video to disk
        video_filename = f"{scan_id}_{video.filename}"
        video_path = os.path.join(UPLOAD_DIR, video_filename)
        with open(video_path, "wb") as buffer:
            shutil.copyfileobj(video.file, buffer)

        # Create scan-specific frame directory
        scan_frame_dir = os.path.join(FRAME_DIR, scan_id)
        os.makedirs(scan_frame_dir, exist_ok=True)

        # Extract frames
        extract_frames(video_path, scan_frame_dir)

        # Load image messages (max 5)
        image_messages = load_image_messages(scan_frame_dir)
        if not image_messages:
            return JSONResponse(status_code=400, content={"error": "No frames extracted."})

        # Get frame paths for database storage
        frame_paths = []
        image_extensions = (".jpg", ".jpeg", ".png")
        for filename in sorted(os.listdir(scan_frame_dir))[:5]:
            if filename.lower().endswith(image_extensions):
                frame_paths.append(os.path.join(scan_frame_dir, filename))

        # Updated system message to handle both analysis and chat
        system_message = {
            "role": "system",
            "content": (
                "You are NuFit — a fun, stylish fashion AI that gives punchy feedback and outfit ratings.\n"
                "Speak like a cool cousin — fun, honest, and baby-simple.\n\n"
                
                "INITIAL OUTFIT ANALYSIS MODE:\n"
                "When analyzing outfit images for the first time, respond ONLY with valid JSON format:\n\n"
                "{\n"
                "  \"score\": \"e.g., 78/100\",\n"
                "  \"fit_line\": \"1–2 fun spoken lines for ElevenLabs (no \\n)\",\n"
                "  \"stylist_says\": \"3-4 line outfit feedback\",\n"
                "  \"what_went_wrong\": \"3-4 lines of what could be better\"\n"
                "}\n\n"
                
                "Scoring Rules:\n"
                "• Matching tones: +10\n"
                "• Contradicting styles: -10\n"
                "• >3 bold colors: -5\n"
                "• No shoes: -15\n"
                "• Slides/formals mismatch: -20\n"
                "• Matching top & bottom: +15\n"
                "• Shoes match outfit: +10\n"
                "• Fits the event: +10\n"
                "• Clashing colors (e.g. red+orange): -10\n\n"
                
                "Adjust with fashion sense if rules are broken but the outfit still slays or follows rules but looks boring.\n\n"
                
                "CHAT MODE:\n"
                "After the initial analysis, respond naturally in conversation. Keep your cool cousin personality:\n"
                "• Give styling tips and advice\n"
                "• Answer questions about fashion, colors, trends\n"
                "• Suggest outfit improvements or alternatives\n"
                "• Be encouraging but honest\n"
                "• Use casual, friendly language\n"
                "• Reference their previous outfit analysis when relevant\n"
                "If user asks anything unrealted to fashion or styling tips, tell user to stick to the topic\n\n"
                
                "IMPORTANT: For initial outfit analysis, return ONLY the JSON object (no markdown, no code blocks). For follow-up chat, respond naturally as NuFit."
            )
        }

        user_text_message = {
            "role": "user",
            "content": "Please analyze the following outfit images using NuFit style rules and give me my FitScore and tips!"
        }

        user_image_message = {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "Assume the person's gender presentation from the image. Use NuFit JSON format for analysis: "
                        "score, fit_line, stylist_says, what_went_wrong. Keep it short and voice-friendly! "
                        "Return only valid JSON, no markdown formatting."
                    )
                }
            ] + image_messages
        }

        # Compose message list and get response
        messages = [system_message, user_text_message, user_image_message]
        reply = chat_with_gpt(messages)

        if not reply:
            return JSONResponse(status_code=500, content={"error": "Failed to get outfit analysis"})

        # Parse JSON response from GPT
        import re
        
        try:
            # Clean the response by removing markdown code blocks if present
            cleaned_reply = reply.strip()
            if cleaned_reply.startswith('```json'):
                cleaned_reply = cleaned_reply[7:]  # Remove ```json
            if cleaned_reply.endswith('```'):
                cleaned_reply = cleaned_reply[:-3]  # Remove ```
            cleaned_reply = cleaned_reply.strip()
            
            # Parse JSON
            parsed_response = json.loads(cleaned_reply)
            
            # Extract individual components - using "score" instead of "fit_score"
            score = parsed_response.get("score", "N/A")
            fit_line = parsed_response.get("fit_line", "")
            stylist_says = parsed_response.get("stylist_says", "")
            what_went_wrong = parsed_response.get("what_went_wrong", "")
            
            # Extract numeric score for database
            score_match = re.search(r'(\d+)/100', score)
            numeric_score = int(score_match.group(1)) if score_match else None
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"JSON parsing error: {e}")
            print(f"Raw reply: {reply}")
            
            # Fallback: extract score from raw reply and use original format
            score_match = re.search(r'(\d+)/100', reply)
            numeric_score = int(score_match.group(1)) if score_match else None
            
            # Return in original format as fallback
            parsed_response = {
                "score": f"{numeric_score}/100" if numeric_score else "N/A",
                "fit_line": "Analysis complete!",
                "stylist_says": reply[:100] + "..." if len(reply) > 100 else reply,
                "what_went_wrong": "Could not parse detailed feedback"
            }
            score = parsed_response["score"]
            fit_line = parsed_response["fit_line"]
            stylist_says = parsed_response["stylist_says"]
            what_went_wrong = parsed_response["what_went_wrong"]

        # Create scan record in database
        scan_success = db.create_scan(
            scan_id=scan_id,
            user_id=user_id,
            video_path=video_path,
            image_paths=frame_paths,
            score=numeric_score,
            feedback=reply  # Store original response for reference
        )

        if not scan_success:
            return JSONResponse(status_code=500, content={"error": "Failed to save scan data"})

        # Store initial chat messages with updated system message for future chats
        chat_system_message = (
            "You are NuFit — a fun, stylish fashion AI that gives punchy feedback and outfit ratings. "
            "You previously analyzed this user's outfit. Continue the conversation naturally, "
            "giving styling tips, answering fashion questions, and being encouraging but honest."
        )
        
        db.add_chat_message(scan_id, "system", chat_system_message)
        db.add_chat_message(scan_id, "user", user_text_message["content"])
        db.add_chat_message(scan_id, "user", "Analyze uploaded outfit images")  # Simplified version of image message
        db.add_chat_message(scan_id, "assistant", reply)

        # Generate audio for the analysis response (base64)
        audio_data = generate_response_audio_base64(reply, scan_id, "analysis")

        # Build response data
        response_data = {
            "scan_id": scan_id,
            "score": score,
            "fit_line": fit_line,
            "stylist_says": stylist_says,
            "what_went_wrong": what_went_wrong,
            "numeric_score": numeric_score
        }
        
        # Add audio data if generation was successful
        if audio_data:
            response_data.update({
                "audio_base64": audio_data["audio_base64"],
                "audio_format": audio_data["audio_format"],
                "audio_filename": audio_data["filename"]
            })

        return response_data

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# New endpoint to serve audio files
@app.get("/audio/{filename}")
async def get_audio_file(filename: str):
    """Serve audio files"""
    try:
        audio_path = os.path.join(AUDIO_DIR, filename)
        if os.path.exists(audio_path):
            return FileResponse(
                audio_path,
                media_type="audio/mpeg",
                filename=filename
            )
        else:
            raise HTTPException(status_code=404, detail="Audio file not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/user/scans/")
async def get_current_user_scans(current_user: dict = Depends(get_authenticated_user)):
    try:
        # This is a simplified approach - you'll need to properly link auth users to scan users
        user_email = current_user["email"]
        
        # Get all scans and filter by email (not efficient, but works for now)
        # In production, you'd want a better way to link auth_users to users table
        all_scans = []  # Implement proper user scan lookup
        
        return {"scans": all_scans}
    except Exception as e:
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
@app.get("/", response_class=HTMLResponse)
async def serve_frontend(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

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