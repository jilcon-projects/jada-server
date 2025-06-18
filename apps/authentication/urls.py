from django.urls import path
from .api import views

app_name = 'authentication'

urlpatterns = [
    path('register', views.RegisterView.as_view(), name='register'),
    path('login', views.LoginView.as_view(), name='login'),
    path('login/google', views.GoogleAuthView.as_view(), name='google_login'),
    path('logout', views.LogoutView.as_view(), name='logout'),
    path('verify-email', views.EmailVerificationView.as_view(), name='verify_email'),
    path('resend-verification', views.ResendEmailVerificationView.as_view(), name='resend_verification'),
    path('complete-profile', views.CompleteProfileView.as_view(), name='complete_profile'),
    path('profile', views.ProfileView.as_view(), name='profile'),
    path('password/request-otp', views.PasswordResetOTPView.as_view(), name='password_request_otp'),
    path('password/resend-otp', views.ResendPasswordResetOTPView.as_view(), name='password_resend_otp'),
    path('password/verify-otp', views.PasswordResetConfirmOTPView.as_view(), name='password_verify_otp'),
    path('password/change', views.ChangePasswordView.as_view(), name='password_change'),
    path('2fa/setup', views.TwoFactorSetupView.as_view(), name='2fa_setup'),
    path('2fa/confirm', views.TwoFactorConfirmView.as_view(), name='2fa_confirm'),
    path('2fa/verify', views.TwoFactorVerifyView.as_view(), name='2fa_verify'),
    path('2fa/disable', views.TwoFactorDisableView.as_view(), name='2fa_disable'),
    path('status', views.UserStatusView.as_view(), name='user_status'),
    path('devices/remembered', views.RememberedDevicesView.as_view(), name='remembered_devices'),
    path('devices/forget', views.ForgetDeviceView.as_view(), name='forget_device'),
]