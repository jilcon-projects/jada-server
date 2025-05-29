import uuid
import requests
from datetime import timedelta
from django.contrib.auth import authenticate, login
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from apps.common.response_builder import ResponseBuilder
from apps.common.response_utils import StandardResponseCodes, StandardResponseMessages
from ..models import DeviceRemembered, PasswordResetOTP, TwoFactorAuth, User
from ..utils import generate_backup_codes, send_password_reset_otp, send_verification_email
from .serializers import (
    ChangePasswordSerializer,
    PasswordResetConfirmOTPSerializer,
    PasswordResetOTPSerializer,
    ProfileCompletionSerializer,
    ProfileUpdateSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
    GoogleAuthSerializer
)


class AuthService:
    @staticmethod
    def register(data, request):
        """Handle user registration logic"""
        serializer = UserRegistrationSerializer(data=data)
        
        if not serializer.is_valid():
            return ResponseBuilder.error('validation', serializer.errors)
        
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
            
            return ResponseBuilder.success('registration', response_data)
            
        except Exception as e:
            return ResponseBuilder.error('registration_failed')
    
    @staticmethod
    def verify_email(token, uid):
        """Handle email verification logic"""
        
        if not token or not uid:
            return ResponseBuilder.error('verification_invalid')
        
        try:
            # Decode user ID
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
            
            # Check if email is already verified
            if user.is_email_verified:
                return ResponseBuilder.success('email_verification', {
                    'email_verified': True,
                    'message': 'Email is already verified!'
                })
            
            # Verify token
            if default_token_generator.check_token(user, token):
                # Mark email as verified
                user.is_email_verified = True
                user.save()
                
                return ResponseBuilder.success('email_verification', {
                    'email_verified': True,
                    'message': 'Email successfully verified!'
                })
            else:
                return ResponseBuilder.error('verification_token_invalid')
                
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return ResponseBuilder.error('verification_link_invalid')
        
    @staticmethod
    def login(data, request):
        """Handle user login logic"""
        
        # Validate input data first
        serializer = UserLoginSerializer(data=data)
        if not serializer.is_valid():
            return ResponseBuilder.error('validation', serializer.errors)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        remember_device = serializer.validated_data.get('remember_device', False)
        
        # Authenticate user
        user = authenticate(request=request, username=email, password=password)
        
        if not user:
            return ResponseBuilder.error('invalid_credentials')
        
        # Check if account is active
        if not user.is_active:
            return ResponseBuilder.error('account_deactivated')
        
        # Check if email is verified
        if not user.is_email_verified:
            return ResponseBuilder.error('email_not_verified')
        
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
            return ResponseBuilder.custom_response(
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
    def verify_google_token(token):
        """Verify Google ID token and return user info"""
        try:
            # Google's token verification endpoint
            google_url = f'https://oauth2.googleapis.com/tokeninfo?id_token={token}'
            
            response = requests.get(google_url)
            
            if response.status_code != 200:
                return None, "Invalid Google token"
            
            user_data = response.json()
            
            # Verify the token is for our app
            if user_data.get('aud') != settings.GOOGLE_OAUTH2_CLIENT_ID:
                return None, "Token not issued for this application"
            
            # Extract user information (removed picture field)
            google_user_info = {
                'email': user_data.get('email'),
                'first_name': user_data.get('given_name', ''),
                'last_name': user_data.get('family_name', ''),
                'google_id': user_data.get('sub'),
                'email_verified': user_data.get('email_verified', False),
            }
            
            return google_user_info, None
            
        except Exception as e:
            return None, f"Error verifying Google token: {str(e)}"
    
    @staticmethod
    def google_auth(data, request):
        """Handle Google Authentication (both sign in and sign up)"""
        serializer = GoogleAuthSerializer(data=data)
        
        if not serializer.is_valid():
            return ResponseBuilder.error('validation', serializer.errors)
        
        google_token = serializer.validated_data['id_token']
        
        # Verify Google token
        google_user_info, error = AuthService.verify_google_token(google_token)
        
        if error:
            return ResponseBuilder.error('google_token_invalid')
        
        email = google_user_info['email']
        
        try:
            # Check if user already exists
            user = User.objects.filter(email=email).first()
            
            if user:
                # EXISTING USER - Sign them in
                updated = False
                
                # Update Google ID if not set
                if not user.google_id and google_user_info['google_id']:
                    user.google_id = google_user_info['google_id']
                    updated = True
                
                # Update names if empty
                if not user.first_name and google_user_info['first_name']:
                    user.first_name = google_user_info['first_name']
                    updated = True
                    
                if not user.last_name and google_user_info['last_name']:
                    user.last_name = google_user_info['last_name']
                    updated = True
                
                # Mark email as verified if Google says it's verified
                if google_user_info['email_verified'] and not user.is_email_verified:
                    user.is_email_verified = True
                    updated = True
                
                if updated:
                    user.save()
                
                return AuthService._complete_google_auth(user, request, is_new_user=False)
            
            else:
                # NEW USER - Create account and sign them in
                user = User.objects.create_user(
                    email=email,
                    username=email,  # Use email as username
                    first_name=google_user_info['first_name'],
                    last_name=google_user_info['last_name'],
                    google_id=google_user_info['google_id'],
                    is_email_verified=google_user_info['email_verified'],
                    password=None  # No password for Google users initially
                )
                
                return AuthService._complete_google_auth(user, request, is_new_user=True)
                
        except Exception as e:
            print(f"Error in Google authentication: {str(e)}")
            return ResponseBuilder.error('google_auth_failed')
    
    @staticmethod
    def _complete_google_auth(user, request, is_new_user=False):
        """Complete Google authentication process"""
        
        # Check if account is active
        if not user.is_active:
            return ResponseBuilder.error('account_deactivated')
        
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
            'is_email_verified': user.is_email_verified,
            'profile_completed': bool(user.first_name and user.last_name),
            'google_user': True,
            'has_password': user.has_usable_password(),
        }
        
        response_data = {
            'user': user_data,
            'access': str(access_token),
            'refresh': str(refresh),
            'is_new_user': is_new_user,
            'requires_2fa': False,  
            'auth_method': 'google',
        }
        
        if is_new_user:
            return ResponseBuilder.success('google_signup', response_data)
        else:
            return ResponseBuilder.success('google_signin', response_data)
        
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
        
        return ResponseBuilder.success('login', response_data)
        
    @staticmethod
    def complete_profile(user, data):
        """Handle user profile completion logic"""
        
        # Check if profile is already completed
        if user.first_name and user.last_name:
            return ResponseBuilder.custom_response(
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
            return ResponseBuilder.error('validation', serializer.errors)
        
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
            
            return ResponseBuilder.success('profile_completed', response_data)
            
        except Exception as e:
            return ResponseBuilder.error('profile_completion_failed')
        
    @staticmethod
    def send_password_reset_otp(data, request):
        """Send password reset OTP"""
        serializer = PasswordResetOTPSerializer(data=data)
        
        if not serializer.is_valid():
            return ResponseBuilder.error('validation', serializer.errors)
        
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # Send OTP
            if send_password_reset_otp(user, request):
                return ResponseBuilder.success('password_reset_otp_sent', {'email': email})
            else:
                return ResponseBuilder.error('password_reset_otp_failed')
                
        except User.DoesNotExist:
            # Return success for security (don't reveal if email exists)
            return ResponseBuilder.success('password_reset_otp_sent', {'email': email})
    
    @staticmethod
    def confirm_password_reset_otp(data, request):
        """Confirm password reset with OTP"""
        serializer = PasswordResetConfirmOTPSerializer(data=data)
        
        if not serializer.is_valid():
            return ResponseBuilder.error('validation', serializer.errors)
        
        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp_code']
        new_password = serializer.validated_data['new_password']
        
        try:
            user = User.objects.get(email=email)
            
            # Verify OTP
            is_valid, message = PasswordResetOTP.verify_otp(user, otp_code)
            
            if is_valid:
                # Set new password
                user.set_password(new_password)
                user.save()
                
                return ResponseBuilder.success('password_reset_confirmed', {
                    'email': user.email,
                    'message': 'Password has been reset successfully'
                })
            else:
                return ResponseBuilder.error('otp_verification_failed')
                
        except User.DoesNotExist:
            return ResponseBuilder.error('otp_verification_failed')
        
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
            
            return ResponseBuilder.success('profile_retrieved', data)
            
        except Exception as e:
            print(f"Error retrieving profile: {str(e)}")
            return ResponseBuilder.custom_response(
                success=False,
                message="Failed to retrieve profile",
                code=StandardResponseCodes.SERVER_ERROR
            )
    
    @staticmethod
    def update_user_profile(user, data):
        """Update user profile"""
        serializer = ProfileUpdateSerializer(user, data=data, partial=True)
        
        if not serializer.is_valid():
            return ResponseBuilder.error('validation', serializer.errors)
        
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
            
            return ResponseBuilder.success('profile_updated', response_data)
            
        except Exception as e:
            print(f"Error updating profile: {str(e)}")
            return ResponseBuilder.error('profile_update_failed')
    
    @staticmethod
    def change_password(user, data):
        """Change user password"""
        serializer = ChangePasswordSerializer(data=data)
        
        if not serializer.is_valid():
            return ResponseBuilder.error('validation', serializer.errors)
        
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        
        # Verify current password
        if not user.check_password(old_password):
            return ResponseBuilder.error('incorrect_current_password')
        
        try:
            # Set new password
            user.set_password(new_password)
            user.save()
            
            return ResponseBuilder.success('password_changed', {
                'email': user.email,
                'message': 'Password has been changed successfully'
            })
            
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return ResponseBuilder.error('password_change_failed')
        
    @staticmethod
    def setup_2fa(user):
        """Set up 2FA for user"""
        try:
            # Check if 2FA is already enabled
            two_factor, created = TwoFactorAuth.objects.get_or_create(user=user)
            
            if two_factor.is_enabled:
                return ResponseBuilder.error('2fa_already_enabled')
            
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
            
            return ResponseBuilder.success('2fa_setup', response_data)
            
        except Exception as e:
            print(f"Error setting up 2FA: {str(e)}")
            return ResponseBuilder.error('2fa_setup_failed')
    
    @staticmethod
    def confirm_2fa(user, otp_token):
        """Confirm 2FA setup"""
        if not otp_token:
            return ResponseBuilder.error('validation', {'otp_token': 'OTP token is required'})
        
        try:
            device = TOTPDevice.objects.filter(user=user).first()
            
            if device and device.verify_token(otp_token):
                device.confirmed = True
                device.save()
                
                # Enable 2FA
                two_factor, created = TwoFactorAuth.objects.get_or_create(user=user)
                two_factor.is_enabled = True
                two_factor.save()
                
                return ResponseBuilder.success('2fa_enabled')
            
            return ResponseBuilder.error('invalid_otp')
            
        except Exception as e:
            print(f"Error confirming 2FA: {str(e)}")
            return ResponseBuilder.error('2fa_confirmation_failed')
    
    @staticmethod
    def verify_2fa(user_id, otp_token, remember_device=False, device_info=None):
        """Verify 2FA during login"""
        if not user_id or not otp_token:
            return ResponseBuilder.error('validation', {'detail': 'User ID and OTP token are required'})
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return ResponseBuilder.error('user_not_found')
        
        # Get user's TOTP device
        device = TOTPDevice.objects.filter(user=user).first()
        
        try:
            if device and device.verify_token(otp_token):
                # Create JWT tokens
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                
                # Remember device if requested
                device_id = None
                if remember_device and device_info:
                    device_id = uuid.uuid4().hex
                    # Generate device name from user agent
                    device_name = "Unknown Device"
                    if 'user_agent' in device_info:
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
                
                return ResponseBuilder.success('login', response_data)
            
            return ResponseBuilder.error('invalid_otp')
            
        except Exception as e:
            print(f"Error verifying 2FA: {str(e)}")
            return ResponseBuilder.error('2fa_verification_failed')
        
    @staticmethod
    def disable_2fa(user, password):
        """Disable 2FA"""
        if not password:
            return ResponseBuilder.error('validation', {'password': 'Password is required to disable 2FA'})
        
        if not user.check_password(password):
            return ResponseBuilder.error('incorrect_password')
                    
        try:
            two_factor = TwoFactorAuth.objects.get(user=user)
            two_factor.is_enabled = False
            two_factor.backup_codes = []
            two_factor.save()
            
            # Remove TOTP devices
            TOTPDevice.objects.filter(user=user).delete()
            
            return ResponseBuilder.success('2fa_disabled')
            
        except TwoFactorAuth.DoesNotExist:
            return ResponseBuilder.error('2fa_not_enabled')
        except Exception as e:
            print(f"Error disabling 2FA: {str(e)}")
            return ResponseBuilder.error('2fa_disable_failed')
        
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
            
            return ResponseBuilder.success('user_status', data)
            
        except Exception as e:
            print(f"Error retrieving user status: {str(e)}")
            return ResponseBuilder.custom_response(
                success=False,
                message=StandardResponseMessages.SERVER_ERROR,
                code=StandardResponseCodes.SERVER_ERROR
            )

    @staticmethod
    def forget_device(user, device_id):
        """Remove a remembered device"""
        if not device_id:
            return ResponseBuilder.error('validation', {'device_id': 'Device ID is required'})
        
        try:
            device = DeviceRemembered.objects.get(
                user=user,
                device_id=device_id
            )
            device.is_active = False
            device.save()
            
            return ResponseBuilder.success('device_forgotten')
            
        except DeviceRemembered.DoesNotExist:
            return ResponseBuilder.error('device_not_found')

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
            
            return ResponseBuilder.success('devices_retrieved', devices_data)
            
        except Exception as e:
            print(f"Error retrieving remembered devices: {str(e)}")
            return ResponseBuilder.custom_response(
                success=False,
                message=StandardResponseMessages.SERVER_ERROR,
                code=StandardResponseCodes.SERVER_ERROR
            )

    @staticmethod
    def logout(refresh_token):
        """Logout user by blacklisting refresh token"""
        if not refresh_token:
            return ResponseBuilder.success('logout')
        
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return ResponseBuilder.success('logout')
            
        except TokenError:
            return ResponseBuilder.error('invalid_token')