import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Email configuration
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
FROM_EMAIL = os.getenv('FROM_EMAIL', SMTP_USERNAME)

def send_email(to_email: str, subject: str, body: str, is_html: bool = False) -> bool:
    """Send email using SMTP"""
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        print("Email credentials not configured")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(body, 'html' if is_html else 'plain'))
        
        # Create SMTP session
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Enable security
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        
        # Send email
        text = msg.as_string()
        server.sendmail(FROM_EMAIL, to_email, text)
        server.quit()
        
        print(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False

def send_password_reset_email(to_email: str, reset_code: str) -> bool:
    """Send password reset email with 4-digit code"""
    subject = "Password Reset Code - NuFitCheck"
    
    body = f"""
    <html>
    <body>
        <h2>Password Reset Request</h2>
        <p>Hi there,</p>
        <p>You requested to reset your password for NuFitCheck. Please use the following 4-digit code to reset your password:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <div style="display: inline-block; background-color: #f0f0f0; border: 2px solid #4CAF50; border-radius: 8px; padding: 20px; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">
                {reset_code}
            </div>
        </div>
        
        <p><strong>This code will expire in 15 minutes.</strong></p>
        <p>Enter this code in the password reset form to create a new password.</p>
        <p>If you didn't request this password reset, please ignore this email.</p>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 12px;">
                For security reasons, never share this code with anyone. 
                NuFitCheck support will never ask for your password reset code.
            </p>
        </div>
        
        <br>
        <p>Best regards,<br>NuFitCheck Team</p>
    </body>
    </html>
    """
    
    return send_email(to_email, subject, body, is_html=True)

# Fallback: Simple console logging if email service is not configured
def log_password_reset_code(email: str, reset_code: str):
    """Log password reset code to console (for development)"""
    print(f"\n{'='*50}")
    print(f"PASSWORD RESET CODE FOR: {email}")
    print(f"Code: {reset_code}")
    print(f"This code expires in 15 minutes")
    print(f"{'='*50}\n")

# Alternative function for plain text emails (if HTML not supported)
def send_password_reset_email_plain(to_email: str, reset_code: str) -> bool:
    """Send password reset email with 4-digit code (plain text version)"""
    subject = "Password Reset Code - NuFitCheck"
    
    body = f"""
Password Reset Request

Hi there,

You requested to reset your password for NuFitCheck. 
Please use the following 4-digit code to reset your password:

    CODE: {reset_code}

This code will expire in 15 minutes.

Enter this code in the password reset form to create a new password.

If you didn't request this password reset, please ignore this email.

For security reasons, never share this code with anyone. 
NuFitCheck support will never ask for your password reset code.

Best regards,
NuFitCheck Team
    """
    
    return send_email(to_email, subject, body, is_html=False)

# Test function to verify email configuration
def test_email_service(test_email: str) -> bool:
    """Test email service configuration"""
    try:
        test_code = "1234"
        return send_password_reset_email(test_email, test_code)
    except Exception as e:
        print(f"Email service test failed: {e}")
        return False