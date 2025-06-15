import random
import string
import uuid
from datetime import timedelta
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from .managers import CustomUserManager


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model with email as username field"""
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True)  
    state = models.CharField(max_length=100, blank=True)    
    ACCOUNT_TYPES = [
        ('business', 'Business'),
        ('individual', 'Individual'),
    ]
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPES, blank=True) 
    google_id = models.CharField(max_length=100, blank=True, null=True, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(blank=True, null=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']  
    class Meta:
        db_table = 'auth_user'
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    @classmethod
    def get_by_uuid(cls, uuid_str):
        """Get user by UUID"""
        try:
            return cls.objects.get(uuid=uuid_str)
        except cls.DoesNotExist:
            return None
        except ValueError:
            return None
    

class PasswordResetOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    max_attempts = models.IntegerField(default=3)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Password Reset OTP for {self.user.email} - {'Used' if self.used else 'Active'}"
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        return not self.used and not self.is_expired() and self.attempts < self.max_attempts
    
    @classmethod
    def generate_otp(cls, user, expiration_minutes=10):
        """Generate a new password reset OTP for user"""
        try:
            # Generate 6-digit OTP
            code = ''.join(random.choices(string.digits, k=6))
            
            # Update or create the OTP for this user
            otp, created = cls.objects.update_or_create(
                user=user,
                defaults={
                    'code': code,
                    'expires_at': timezone.now() + timedelta(minutes=expiration_minutes),
                    'used': False,
                    'attempts': 0
                }
            )
            
            return otp
        except Exception as e:
            print(f"Error generating OTP: {str(e)}")
            raise

    @classmethod
    def verify_otp(cls, user, code):
        """Verify OTP and mark as used if valid"""
        try:
            # Try to get the OTP for this user
            try:
                otp = cls.objects.get(user=user)
            except cls.DoesNotExist:
                return False, "Invalid OTP"
            
            # Check if the OTP code matches
            if otp.code != code:
                # Increment attempts
                otp.attempts += 1
                otp.save()
                
                if otp.attempts >= otp.max_attempts:
                    return False, "Too many attempts. Please request a new OTP"
                return False, f"Invalid OTP. {otp.max_attempts - otp.attempts} attempts remaining"
            
            # Check if OTP is already used
            if otp.used:
                return False, "OTP has already been used"
            
            # Check if OTP is expired
            if otp.is_expired():
                return False, "OTP has expired"
            
            # If we get here, the OTP is valid
            otp.used = True
            otp.save()
            return True, "OTP verified successfully"
                
        except Exception as e:
            print(f"Error verifying OTP: {str(e)}")
            return False, "Invalid OTP"
    

class TwoFactorAuth(models.Model):
    """Model to track 2FA settings for users"""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='two_factor')
    is_enabled = models.BooleanField(default=False)
    backup_codes = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"2FA for {self.user.email}"


class DeviceRemembered(models.Model):
    """Model to track remembered devices for users"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='remembered_devices')
    device_id = models.CharField(max_length=255)
    device_name = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'device_id']
    
    def __str__(self):
        return f"Device {self.device_id} for {self.user.email}"
    
    def is_expired(self):
        return timezone.now() > self.expires_at