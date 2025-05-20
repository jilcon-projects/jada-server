import uuid
from datetime import timedelta
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from apps.common.response_utils import (
    create_response_data,
    StandardResponseCodes,
    StandardResponseMessages
)
from ..models import DeviceRemembered, PasswordResetOTP, TwoFactorAuth, User
from ..utils import generate_backup_codes, send_password_reset_otp, send_verification_email
from .serializers import (
    ChangePasswordSerializer,
    PasswordResetConfirmOTPSerializer,
    PasswordResetOTPSerializer,
    ProfileCompletionSerializer,
    ProfileUpdateSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer
)


class AuthServiceResponse:
    def __init__(self, success: bool, message: str, code: str, data=None, errors=None):
        self.success = success
        self.message = message
        self.code = code
        self.data = data
        self.errors = errors
    
    def to_dict(self):
        """Convert to dictionary matching your standard response format"""
        return create_response_data(
            success=self.success,
            message=self.message,
            response_code=self.code,
            data=self.data,
            errors=self.errors
        )

class AuthService:
    @staticmethod
    def register(data, request):
        """Handle user registration logic"""
        serializer = UserRegistrationSerializer(data=data)
        
        if not serializer.is_valid():
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors=serializer.errors
            )
        
        try:
            # Save the user
            user = serializer.save()
            
            # Send verification email
            verification_sent = send_verification_email(user, request)
            
            # Create JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Prepare user data
            user_data = {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'is_email_verified': user.is_email_verified,
                'profile_completed': False,
            }
            
            response_data = {
                'user': user_data,
                'access': str(access_token),
                'refresh': str(refresh),
                'verification_email_sent': verification_sent
            }
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.REGISTRATION_SUCCESSFUL,
                code=StandardResponseCodes.REGISTRATION_SUCCESSFUL,
                data=response_data
            )
            
        except Exception as e:
            return AuthServiceResponse(
                success=False,
                message="Registration process failed",
                code=StandardResponseCodes.REGISTRATION_PROCESS_FAILED,
                data=None
            )
    
    @staticmethod
    def verify_email(token, uid):
        """Handle email verification logic"""
        
        if not token or not uid:
            return AuthServiceResponse(
                success=False,
                message="Invalid verification link. Token or UID missing.",
                code=StandardResponseCodes.VERIFICATION_INVALID
            )
        
        try:
            # Decode user ID
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
            
            # Check if email is already verified
            if user.is_email_verified:
                return AuthServiceResponse(
                    success=True,
                    message="Email is already verified",
                    code=StandardResponseCodes.EMAIL_VERIFICATION_SUCCESSFUL,
                    data={
                        'email_verified': True,
                        'message': 'Email is already verified!'
                    }
                )
            
            # Verify token
            if default_token_generator.check_token(user, token):
                # Mark email as verified
                user.is_email_verified = True
                user.save()
                
                return AuthServiceResponse(
                    success=True,
                    message=StandardResponseMessages.EMAIL_VERIFICATION_SUCCESSFUL,
                    code=StandardResponseCodes.EMAIL_VERIFICATION_SUCCESSFUL,
                    data={
                        'email_verified': True,
                        'message': 'Email successfully verified!'
                    }
                )
            else:
                return AuthServiceResponse(
                    success=False,
                    message="Invalid or expired verification link.",
                    code=StandardResponseCodes.VERIFICATION_TOKEN_INVALID
                )
                
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return AuthServiceResponse(
                success=False,
                message="Invalid verification link.",
                code=StandardResponseCodes.VERIFICATION_LINK_INVALID
            )
        
    @staticmethod
    def login(data, request):
        """Handle user login logic"""
        
        # Validate input data first
        serializer = UserLoginSerializer(data=data)
        if not serializer.is_valid():
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors=serializer.errors
            )
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        remember_device = serializer.validated_data.get('remember_device', False)
        
        # Authenticate user
        user = authenticate(request=request, username=email, password=password)
        
        if not user:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.INVALID_CREDENTIALS,
                code=StandardResponseCodes.INVALID_CREDENTIALS
            )
        
        # Check if account is active
        if not user.is_active:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.ACCOUNT_DEACTIVATED,
                code=StandardResponseCodes.ACCOUNT_DEACTIVATED
            )
        
        # Check if email is verified
        if not user.is_email_verified:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.EMAIL_NOT_VERIFIED,
                code=StandardResponseCodes.EMAIL_NOT_VERIFIED
            )
        
        # Check if 2FA is enabled
        if hasattr(user, 'two_factor') and user.two_factor.is_enabled:
            # Check if device is remembered
            device_id = data.get('device_id')
            if device_id:
                remembered_device = DeviceRemembered.objects.filter(
                    user=user,
                    device_id=device_id,
                    is_active=True,
                    expires_at__gt=timezone.now()
                ).first()
                
                if remembered_device:
                    # Device is remembered, proceed with login
                    return AuthService._complete_login(user, request, remember_device, data)
            
            # Require 2FA verification
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.TWO_FA_REQUIRED,
                code=StandardResponseCodes.TWO_FA_REQUIRED,
                data={
                    'requires_2fa': True,
                    'user_id': user.id
                }
            )
        
        # No 2FA required, complete login
        return AuthService._complete_login(user, request, remember_device, data)
    
    @staticmethod
    def get_device_name(request):
        """Generate a descriptive device name from user agent information"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Default device name
        device_name = "Unknown Device"
        
        # Simple device detection logic
        if 'iPhone' in user_agent:
            device_name = "iPhone"
        elif 'iPad' in user_agent:
            device_name = "iPad"
        elif 'Android' in user_agent:
            if 'Mobile' in user_agent:
                device_name = "Android Phone"
            else:
                device_name = "Android Tablet"
        elif 'Windows' in user_agent:
            device_name = "Windows PC"
        elif 'Macintosh' in user_agent or 'Mac OS' in user_agent:
            device_name = "Mac"
        elif 'Linux' in user_agent:
            if 'Mobile' in user_agent:
                device_name = "Linux Phone"
            else:
                device_name = "Linux PC"
        elif 'CrOS' in user_agent:
            device_name = "Chromebook"
        
        # Add browser info to make it more specific
        if 'Chrome' in user_agent and 'Edg' not in user_agent and 'OPR' not in user_agent:
            browser = "Chrome"
        elif 'Firefox' in user_agent:
            browser = "Firefox"
        elif 'Safari' in user_agent and 'Chrome' not in user_agent:
            browser = "Safari"
        elif 'Edg' in user_agent:
            browser = "Edge"
        elif 'OPR' in user_agent or 'Opera' in user_agent:
            browser = "Opera"
        else:
            browser = "Browser"
        
        return f"{device_name} ({browser})"
    
    @staticmethod
    def _complete_login(user, request, remember_device, data):
        """Complete the login process and return tokens"""
        
        # Perform Django login
        login(request, user)
        
        # Create JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        # Prepare user data
        user_data = {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'profile_completed': bool(user.first_name and user.last_name),
        }
        
        response_data = {
            'user': user_data,
            'access': str(access_token),
            'refresh': str(refresh),
            'requires_2fa': False,
        }
        
        # Remember device if requested
        if remember_device:
            device_id = uuid.uuid4().hex
            device_name = AuthService.get_device_name(request)
            DeviceRemembered.objects.create(
                user=user,
                device_id=device_id,
                device_name=device_name,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                expires_at=timezone.now() + timedelta(days=30)
            )
            response_data['device_id'] = device_id
        
        return AuthServiceResponse(
            success=True,
            message=StandardResponseMessages.LOGIN_SUCCESSFUL,
            code=StandardResponseCodes.LOGIN_SUCCESSFUL,
            data=response_data
        )
        
    @staticmethod
    def complete_profile(user, data):
        """Handle user profile completion logic"""
        
        # Check if profile is already completed
        if user.first_name and user.last_name:
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.PROFILE_ALREADY_COMPLETED,
                code=StandardResponseCodes.PROFILE_ALREADY_COMPLETED,
                data={
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'phone': user.phone,
                        'country': user.country,
                        'state': user.state,
                        'account_type': user.account_type,
                        'profile_completed': True,
                    }
                }
            )
        
        # Validate and save profile data
        serializer = ProfileCompletionSerializer(user, data=data, partial=False)
        
        if not serializer.is_valid():
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors=serializer.errors
            )
        
        try:
            # Save the profile
            user = serializer.save()
            
            # Prepare response data
            response_data = {
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone': user.phone,
                    'country': user.country,
                    'state': user.state,
                    'account_type': user.account_type,
                    'profile_completed': True,
                }
            }
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.PROFILE_COMPLETED_SUCCESSFUL,
                code=StandardResponseCodes.PROFILE_COMPLETED_SUCCESSFUL,
                data=response_data
            )
            
        except Exception as e:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.PROFILE_COMPLETION_FAILED,
                code=StandardResponseCodes.PROFILE_COMPLETION_FAILED,
                data=None
            )
        
    @staticmethod
    def send_password_reset_otp(data, request):
        """Send password reset OTP"""
        serializer = PasswordResetOTPSerializer(data=data)
        
        if not serializer.is_valid():
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors=serializer.errors
            )
        
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # Send OTP
            if send_password_reset_otp(user, request):
                return AuthServiceResponse(
                    success=True,
                    message="Password reset code sent to your email",
                    code=StandardResponseCodes.PASSWORD_RESET_OTP_SENT,
                    data={'email': email}
                )
            else:
                return AuthServiceResponse(
                    success=False,
                    message="Failed to send password reset code",
                    code=StandardResponseCodes.PASSWORD_RESET_OTP_FAILED
                )
                
        except User.DoesNotExist:
            return AuthServiceResponse(
                success=True,
                message="If the email exists, a password reset code has been sent",
                code=StandardResponseCodes.PASSWORD_RESET_OTP_SENT,
                data={'email': email}
            )
    
    @staticmethod
    def confirm_password_reset_otp(data, request):
        """Confirm password reset with OTP"""
        serializer = PasswordResetConfirmOTPSerializer(data=data)
        
        if not serializer.is_valid():
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors=serializer.errors
            )
        
        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp_code']
        new_password = serializer.validated_data['new_password']
        
        # Console logging for debugging
        print(f"\nPassword reset OTP attempt:")
        print(f"Email: {email}")
        print(f"OTP Code: {otp_code}")
        
        try:
            user = User.objects.get(email=email)
            
            # Verify OTP
            is_valid, message = PasswordResetOTP.verify_otp(user, otp_code)
            
            if is_valid:
                # Set new password
                user.set_password(new_password)
                user.save()
                
                print(f"Password reset successful for: {user.email}")
                
                return AuthServiceResponse(
                    success=True,
                    message=StandardResponseMessages.PASSWORD_RESET_CONFIRMED,
                    code=StandardResponseCodes.PASSWORD_RESET_CONFIRMED,
                    data={
                        'email': user.email,
                        'message': 'Password has been reset successfully'
                    }
                )
            else:
                print(f"Password reset failed for {user.email}: {message}")
                return AuthServiceResponse(
                    success=False,
                    message=message,
                    code=StandardResponseCodes.OTP_VERIFICATION_FAILED
                )
                
        except User.DoesNotExist:
            print(f"Password reset attempt for non-existent email: {email}")
            return AuthServiceResponse(
                success=False,
                message="Invalid email or OTP",
                code=StandardResponseCodes.OTP_VERIFICATION_FAILED
            )
        
    @staticmethod
    def get_user_profile(user):
        """Get user profile data"""
        try:
            data = {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone': user.phone,
                'country': user.country,
                'state': user.state,
                'account_type': user.account_type,
                'is_email_verified': user.is_email_verified,
                'date_joined': user.date_joined,
                'has_2fa': hasattr(user, 'two_factor') and user.two_factor.is_enabled,
                'profile_completed': bool(user.first_name and user.last_name),
            }
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.PROFILE_RETRIEVED_SUCCESSFUL,
                code=StandardResponseCodes.PROFILE_RETRIEVED_SUCCESSFUL,
                data=data
            )
            
        except Exception as e:
            print(f"Error retrieving profile: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message="Failed to retrieve profile",
                code=StandardResponseCodes.SERVER_ERROR,
                data=None
            )
    
    @staticmethod
    def update_user_profile(user, data):
        """Update user profile"""
        serializer = ProfileUpdateSerializer(user, data=data, partial=True)
        
        if not serializer.is_valid():
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors=serializer.errors
            )
        
        try:
            # Save the updated profile
            user = serializer.save()
            
            # Prepare response data
            response_data = {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone': user.phone,
                'country': user.country,
                'state': user.state,
                'account_type': user.account_type,
                'profile_completed': bool(user.first_name and user.last_name),
            }
            
            print(f"Profile updated for user: {user.email}")
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.PROFILE_UPDATED_SUCCESSFUL,
                code=StandardResponseCodes.PROFILE_UPDATED_SUCCESSFUL,
                data=response_data
            )
            
        except Exception as e:
            print(f"Error updating profile: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.PROFILE_UPDATE_FAILED,
                code=StandardResponseCodes.PROFILE_UPDATE_FAILED,
                data=None
            )
    
    @staticmethod
    def change_password(user, data):
        """Change user password"""
        serializer = ChangePasswordSerializer(data=data)
        
        if not serializer.is_valid():
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors=serializer.errors
            )
        
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        
        # Verify current password
        if not user.check_password(old_password):
            print(f"Incorrect password attempt for user: {user.email}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.INCORRECT_CURRENT_PASSWORD,
                code=StandardResponseCodes.INCORRECT_CURRENT_PASSWORD,
                data=None
            )
        
        try:
            # Set new password
            user.set_password(new_password)
            user.save()
            
            print(f"Password changed successfully for user: {user.email}")
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.PASSWORD_CHANGED_SUCCESSFUL,
                code=StandardResponseCodes.PASSWORD_CHANGED_SUCCESSFUL,
                data={
                    'email': user.email,
                    'message': 'Password has been changed successfully'
                }
            )
            
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.PASSWORD_CHANGE_FAILED,
                code=StandardResponseCodes.PASSWORD_CHANGE_FAILED,
                data=None
            )
        
    @staticmethod
    def setup_2fa(user):
        """Set up 2FA for user"""
        try:
            # Check if 2FA is already enabled
            two_factor, created = TwoFactorAuth.objects.get_or_create(user=user)
            
            if two_factor.is_enabled:
                return AuthServiceResponse(
                    success=False,
                    message=StandardResponseMessages.TWO_FA_ALREADY_ENABLED,
                    code=StandardResponseCodes.TWO_FA_ALREADY_ENABLED
                )
            
            # Create TOTP device
            device = TOTPDevice.objects.filter(user=user).first()
            
            if not device:
                device = TOTPDevice.objects.create(
                    user=user,
                    name='default',
                    confirmed=False
                )
            
            # Generate backup codes
            backup_codes = generate_backup_codes()
            two_factor.backup_codes = backup_codes
            two_factor.save()
            
            response_data = {
                'qr_url': device.config_url,
                'secret_key': device.bin_key.hex(),
                'backup_codes': backup_codes
            }
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.TWO_FA_SETUP_INITIATED,
                code=StandardResponseCodes.TWO_FA_SETUP_INITIATED,
                data=response_data
            )
            
        except Exception as e:
            print(f"Error setting up 2FA: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.TWO_FA_SETUP_FAILED,
                code=StandardResponseCodes.TWO_FA_SETUP_FAILED
            )
    
    @staticmethod
    def confirm_2fa(user, otp_token):
        """Confirm 2FA setup"""
        if not otp_token:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors={'otp_token': 'OTP token is required'}
            )
        
        try:
            device = TOTPDevice.objects.filter(user=user).first()
            
            if device and device.verify_token(otp_token):
                device.confirmed = True
                device.save()
                
                # Enable 2FA
                two_factor, created = TwoFactorAuth.objects.get_or_create(user=user)
                two_factor.is_enabled = True
                two_factor.save()
                
                return AuthServiceResponse(
                    success=True,
                    message=StandardResponseMessages.TWO_FA_ENABLED,
                    code=StandardResponseCodes.TWO_FA_ENABLED
                )
            
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.INVALID_OTP,
                code=StandardResponseCodes.INVALID_OTP
            )
            
        except Exception as e:
            print(f"Error confirming 2FA: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.TWO_FA_CONFIRMATION_FAILED,
                code=StandardResponseCodes.TWO_FA_CONFIRMATION_FAILED
            )
    
    @staticmethod
    def verify_2fa(user_id, otp_token, remember_device=False, device_info=None):
        """Verify 2FA during login"""
        if not user_id or not otp_token:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors={'detail': 'User ID and OTP token are required'}
            )
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.USER_NOT_FOUND,
                code=StandardResponseCodes.USER_NOT_FOUND
            )
        
        # Get user's TOTP device
        device = TOTPDevice.objects.filter(user=user).first()
        
        try:
            if device and device.verify_token(otp_token):
                # Create JWT tokens
                from rest_framework_simplejwt.tokens import RefreshToken
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                
                # Remember device if requested
                device_id = None
                if remember_device and device_info:
                    device_id = uuid.uuid4().hex
                    # Generate device name from user agent
                    device_name = "Unknown Device"
                    if 'user_agent' in device_info:
                        # Simple detection from user_agent string
                        user_agent = device_info.get('user_agent', '')
                        if 'iPhone' in user_agent:
                            device_name = "iPhone"
                        elif 'iPad' in user_agent:
                            device_name = "iPad"
                        elif 'Android' in user_agent:
                            device_name = "Android Device"
                        elif 'Windows' in user_agent:
                            device_name = "Windows PC"
                        elif 'Macintosh' in user_agent:
                            device_name = "Mac"
                    
                    DeviceRemembered.objects.create(
                        user=user,
                        device_id=device_id,
                        device_name=device_name,
                        ip_address=device_info.get('ip_address', ''),
                        user_agent=device_info.get('user_agent', ''),
                        expires_at=timezone.now() + timedelta(days=30)
                    )
                
                # Prepare user data
                user_data = {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'profile_completed': bool(user.first_name and user.last_name),
                }
                
                response_data = {
                    'user': user_data,
                    'access': str(access_token),
                    'refresh': str(refresh),
                }
                
                if device_id:
                    response_data['device_id'] = device_id
                
                return AuthServiceResponse(
                    success=True,
                    message=StandardResponseMessages.LOGIN_SUCCESSFUL,
                    code=StandardResponseCodes.LOGIN_SUCCESSFUL,
                    data=response_data
                )
            
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.INVALID_OTP,
                code=StandardResponseCodes.INVALID_OTP
            )
            
        except Exception as e:
            print(f"Error verifying 2FA: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.TWO_FA_VERIFICATION_FAILED,
                code=StandardResponseCodes.TWO_FA_VERIFICATION_FAILED
            )
        
    @staticmethod
    def disable_2fa(user, password):
        """Disable 2FA"""
        if not password:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors={'password': 'Password is required to disable 2FA'}
            )
        
        if not user.check_password(password):
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.INCORRECT_PASSWORD,
                code=StandardResponseCodes.INCORRECT_PASSWORD
            )
                    
        try:
            two_factor = TwoFactorAuth.objects.get(user=user)
            two_factor.is_enabled = False
            two_factor.backup_codes = []
            two_factor.save()
            
            # Remove TOTP devices
            TOTPDevice.objects.filter(user=user).delete()
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.TWO_FA_DISABLED,
                code=StandardResponseCodes.TWO_FA_DISABLED
            )
            
        except TwoFactorAuth.DoesNotExist:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.TWO_FA_NOT_ENABLED,
                code=StandardResponseCodes.TWO_FA_NOT_ENABLED
            )
        except Exception as e:
            print(f"Error disabling 2FA: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.TWO_FA_DISABLE_FAILED,
                code=StandardResponseCodes.TWO_FA_DISABLE_FAILED
            )
        
    @staticmethod
    def get_user_status(user):
        """Get user status and authentication information"""
        try:
            # Check 2FA status
            has_2fa = False
            if hasattr(user, 'two_factor'):
                has_2fa = user.two_factor.is_enabled
            
            # Check remembered devices
            remembered_devices = DeviceRemembered.objects.filter(
                user=user,
                is_active=True,
                expires_at__gt=timezone.now()
            ).count()
            
            data = {
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_active': user.is_active,
                    'is_email_verified': user.is_email_verified,
                    'account_type': user.account_type,
                    'date_joined': user.date_joined,
                    'last_login': user.last_login,
                    'profile_completed': bool(user.first_name and user.last_name),
                },
                'authentication': {
                    'has_2fa': has_2fa,
                    'remembered_devices_count': remembered_devices,
                    'is_staff': user.is_staff,
                }
            }
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.USER_STATUS_RETRIEVED,
                code=StandardResponseCodes.USER_STATUS_RETRIEVED,
                data=data
            )
        except Exception as e:
            print(f"Error retrieving user status: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.SERVER_ERROR,
                code=StandardResponseCodes.SERVER_ERROR
            )

    @staticmethod
    def forget_device(user, device_id):
        """Remove a remembered device"""
        if not device_id:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.VALIDATION_ERROR,
                code=StandardResponseCodes.VALIDATION_ERROR,
                errors={'device_id': 'Device ID is required'}
            )
        
        try:
            device = DeviceRemembered.objects.get(
                user=user,
                device_id=device_id
            )
            device.is_active = False
            device.save()
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.DEVICE_FORGOTTEN,
                code=StandardResponseCodes.DEVICE_FORGOTTEN
            )
            
        except DeviceRemembered.DoesNotExist:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.DEVICE_NOT_FOUND,
                code=StandardResponseCodes.DEVICE_NOT_FOUND
            )

    @staticmethod
    def get_remembered_devices(user, current_device_id=None):
        """Get list of all remembered devices for the user"""
        try:
            devices = DeviceRemembered.objects.filter(
                user=user,
                is_active=True,
                expires_at__gt=timezone.now()
            ).order_by('-created_at')
            
            devices_data = []
            for device in devices:
                devices_data.append({
                    'device_id': device.device_id,
                    'device_name': device.device_name,
                    'ip_address': device.ip_address,
                    'created_at': device.created_at,
                    'expires_at': device.expires_at,
                    'is_current': device.device_id == current_device_id
                })
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.REMEMBERED_DEVICES_RETRIEVED,
                code=StandardResponseCodes.REMEMBERED_DEVICES_RETRIEVED,
                data=devices_data
            )
        except Exception as e:
            print(f"Error retrieving remembered devices: {str(e)}")
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.SERVER_ERROR,
                code=StandardResponseCodes.SERVER_ERROR
            )

    @staticmethod
    def logout(refresh_token):
        """Logout user by blacklisting refresh token"""
        if not refresh_token:
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.LOGOUT_SUCCESSFUL,
                code=StandardResponseCodes.LOGOUT_SUCCESSFUL
            )
        
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return AuthServiceResponse(
                success=True,
                message=StandardResponseMessages.LOGOUT_SUCCESSFUL,
                code=StandardResponseCodes.LOGOUT_SUCCESSFUL
            )
        except TokenError:
            return AuthServiceResponse(
                success=False,
                message=StandardResponseMessages.INVALID_TOKEN,
                code=StandardResponseCodes.INVALID_TOKEN
            )










            


