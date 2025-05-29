import traceback
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView

from apps.common.response_utils import server_error_response
from .service import AuthService
from .serializers import (
    ChangePasswordSerializer,
    EmailVerificationSerializer,
    ForgetDeviceSerializer,
    LogoutSerializer,
    PasswordResetConfirmOTPSerializer,
    PasswordResetOTPSerializer,
    ProfileCompletionSerializer,
    ProfileUpdateSerializer,
    TwoFactorAuthSerializer,
    TwoFactorDisableSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer,
    GoogleAuthSerializer
)


class RegisterView(APIView):
    """User registration endpoint"""
    permission_classes = [AllowAny]
    serializer_class = UserRegistrationSerializer
    
    def post(self, request):
        try:
            result = AuthService.register(request.data, request)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Registration error: {error_trace}")
            return server_error_response()


class EmailVerificationView(APIView):
    """Verify user email with token"""
    permission_classes = [AllowAny]
    serializer_class = EmailVerificationSerializer
    
    def get(self, request):
        try:
            token = request.GET.get('token')
            uid = request.GET.get('uid')
            result = AuthService.verify_email(token, uid)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Email verification error: {error_trace}")
            return server_error_response()


class LoginView(APIView):
    """User login with JWT tokens"""
    permission_classes = [AllowAny]
    serializer_class = UserLoginSerializer
    
    def post(self, request):
        try:
            result = AuthService.login(request.data, request)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Login error: {error_trace}")
            return server_error_response()
        

class GoogleAuthView(APIView):
    """
    Single Google Authentication endpoint
    """
    permission_classes = [AllowAny]
    serializer_class = GoogleAuthSerializer
    
    def post(self, request):
        try:
            result = AuthService.google_auth(request.data, request)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Google authentication error: {error_trace}")
            return server_error_response()


class CompleteProfileView(APIView):
    """Complete user profile after registration"""
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileCompletionSerializer
    
    def post(self, request):
        try:
            result = AuthService.complete_profile(request.user, request.data)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Profile completion error: {error_trace}")
            return server_error_response()


class PasswordResetOTPView(APIView):
    """Send password reset OTP"""
    permission_classes = [AllowAny]
    serializer_class = PasswordResetOTPSerializer
    
    def post(self, request):
        try:
            result = AuthService.send_password_reset_otp(request.data, request)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Password reset OTP error: {error_trace}")
            return server_error_response()


class PasswordResetConfirmOTPView(APIView):
    """Confirm password reset with OTP"""
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmOTPSerializer
    
    def post(self, request):
        try:
            result = AuthService.confirm_password_reset_otp(request.data, request)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Password reset confirm OTP error: {error_trace}")
            return server_error_response()


class ChangePasswordView(APIView):
    """Change password for authenticated user"""
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer
    
    def post(self, request):
        try:
            result = AuthService.change_password(request.user, request.data)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Password change error: {error_trace}")
            return server_error_response()


class ProfileView(APIView):
    """Get and update user profile"""
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileUpdateSerializer
    
    def get(self, request):
        """Get user profile"""
        try:
            result = AuthService.get_user_profile(request.user)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Profile retrieval error: {error_trace}")
            return server_error_response()
    
    def put(self, request):
        """Update user profile"""
        try:
            result = AuthService.update_user_profile(request.user, request.data)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Profile update error: {error_trace}")
            return server_error_response()


class TwoFactorSetupView(APIView):
    """Setup 2FA for user"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            result = AuthService.setup_2fa(request.user)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"2FA setup error: {error_trace}")
            return server_error_response()


class TwoFactorConfirmView(APIView):
    """Confirm 2FA setup"""
    permission_classes = [IsAuthenticated]
    serializer_class = TwoFactorAuthSerializer
    
    def post(self, request):
        try:
            result = AuthService.confirm_2fa(
                user=request.user, 
                otp_token=request.data.get('otp_token')
            )
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"2FA confirmation error: {error_trace}")
            return server_error_response()


class TwoFactorVerifyView(APIView):
    """Verify 2FA token and return JWT tokens"""
    permission_classes = [AllowAny]
    serializer_class = TwoFactorAuthSerializer
    
    def post(self, request):
        try:
            # Simplified device info preparation
            device_info = {
                'ip_address': request.META.get('REMOTE_ADDR', ''),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')
            }
            
            result = AuthService.verify_2fa(user_id=request.data.get('user_id'), otp_token=request.data.get('otp_token'),
                remember_device=request.data.get('remember_device', False), device_info=device_info)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"2FA verification error: {error_trace}")
            return server_error_response()


class TwoFactorDisableView(APIView):
    """Disable 2FA"""
    permission_classes = [IsAuthenticated]
    serializer_class = TwoFactorDisableSerializer
    
    def post(self, request):
        try:
            result = AuthService.disable_2fa(
                user=request.user,
                password=request.data.get('password')
            )
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"2FA disable error: {error_trace}")
            return server_error_response()


class UserStatusView(GenericAPIView):
    """Get current user status and authentication info"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            result = AuthService.get_user_status(request.user)
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"User status error: {error_trace}")
            return server_error_response()


class ForgetDeviceView(APIView):
    """Remove a remembered device"""
    permission_classes = [IsAuthenticated]
    serializer_class = ForgetDeviceSerializer
    
    def post(self, request):
        try:
            result = AuthService.forget_device(
                user=request.user,
                device_id=request.data.get('device_id')
            )
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Forget device error: {error_trace}")
            return server_error_response()


class RememberedDevicesView(GenericAPIView):
    """Get list of remembered devices"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            current_device_id = request.headers.get('Device-ID')
            result = AuthService.get_remembered_devices(
                user=request.user,
                current_device_id=current_device_id
            )
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Remembered devices error: {error_trace}")
            return server_error_response()


class LogoutView(APIView):
    """User logout with JWT blacklisting"""
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer
    
    def post(self, request):
        try:
            result = AuthService.logout(request.data.get("refresh"))
            return result.to_response()
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"Logout error: {error_trace}")
            return server_error_response()
