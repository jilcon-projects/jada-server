import random
import string
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from .models import User, PasswordResetOTP
from .email_service import send_custom_email
from django.utils.encoding import force_str
import logging

logger = logging.getLogger(__name__)


def send_verification_email(user, request):
    """Send email verification link to user"""
    try:
       
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Get domain
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
        
        verification_url = f"{protocol}://{domain}/api/auth/verify-email/?token={token}&uid={uid}"
        
        # Email content
        html_content = f"""
        <html>
        <body>
            <h2>Email Verification</h2>
            <p>Hi {user.username},</p>
            <p>Please verify your email address by clicking the link below:</p>
            <div style="padding: 20px; border: 2px solid #007bff; border-radius: 5px; margin: 20px 0; background-color: #f8f9fa;">
                <a href="{verification_url}" style="color: #007bff; text-decoration: none; font-weight: bold;">
                    Click here to verify your email
                </a>
            </div>
            <p style="color: red; font-weight: bold;">⏰ This link will expire in 24 hours.</p>
            <p>If you didn't create this account, please ignore this email.</p>
            <p>Best regards,<br>The BuildCalc Team</p>
        </body>
        </html>
        """
        
        text_content = f"""
Hi {user.username},

Please verify your email address by clicking this link:

{verification_url}

This link will expire in 24 hours.

If you didn't create this account, please ignore this email.

Best regards,
The BuildCalc Team
        """.strip()
                
        # Send the email
        result = send_custom_email(
            to_email=user.email,
            to_name=user.username,
            subject="Email Verification Code - BuildCalc",
            html_content=html_content,
            text_content=text_content
        )
        
        # Console logging
        print("\n" + "="*50)
        print("EMAIL VERIFICATION DEBUG")
        print("="*50)
        print(f"To: {user.email}")
        print(f"Verification URL: {verification_url}")
        print(f"Result: {result}")
        print("="*50 + "\n")
        
        logger.info(f"Verification email sent to {user.email}: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to send verification email: {str(e)}")
        print(f"Failed to send verification email: {str(e)}")
        return False
    

def send_password_reset_otp(user, request):
    """Send password reset OTP"""
    try:
        # Generate OTP (expires in 1 minute)
        otp = PasswordResetOTP.generate_otp(user, expiration_minutes=1)
        
        # Email content
        html_content = f"""
        <html>
        <body>
            <h2>Password Reset Code</h2>
            <p>Hi {user.username},</p>
            <p>Your password reset code is:</p>
            <div style="font-size: 32px; font-weight: bold; color: #007bff; text-align: center; padding: 20px; border: 2px solid #007bff; border-radius: 5px; margin: 20px 0; background-color: #f8f9fa;">
                {otp.code}
            </div>
            <p style="color: red; font-weight: bold;">⏰ This code will expire in 1 minute.</p>
            <p>Enter this code along with your new password to reset your account password.</p>
            <p>If you didn't request this password reset, please ignore this email.</p>
            <p>Best regards,<br>The BuildCalc Team</p>
        </body>
        </html>
        """
        
        text_content = f"""
Hi {user.username},

Your password reset code is:

{otp.code}

This code will expire in 1 minute.

Enter this code along with your new password to reset your account password.

If you didn't request this password reset, please ignore this email.

Best regards,
The BuildCalc Team
        """.strip()
        
        
        # Send the email
        result = send_custom_email(
            to_email=user.email,
            to_name=user.username,
            subject="Password Reset Code - BuildCalc",
            html_content=html_content,
            text_content=text_content
        )
        
        # Console logging for debugging
        print("\n" + "="*50)
        print("PASSWORD RESET OTP DEBUG")
        print("="*50)
        print(f"To: {user.email}")
        print(f"OTP Code: {otp.code}")
        print(f"Expires at: {otp.expires_at}")
        print(f"Valid for: 1 minute")
        print(f"Result: {result}")
        print("="*50 + "\n")
        
        return result
        
    except Exception as e:
        print(f"Failed to send password reset OTP: {str(e)}")
        return False


def generate_backup_codes():
    """Generate backup codes for 2FA"""
    codes = []
    for _ in range(10):
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        codes.append(code)
    return codes

def generate_device_id():
    """Generate a unique device ID"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))


def format_phone_number(phone):
    """Format phone number for display"""
    if not phone:
        return ""
    
    # Remove all non-digit characters
    digits = ''.join(filter(str.isdigit, phone))
    
    # Format based on length
    if len(digits) == 10:
        return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    elif len(digits) == 11 and digits[0] == '1':
        return f"+1 ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
    else:
        return phone