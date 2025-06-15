import random
import re
import string
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from ..models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30)
    id = serializers.UUIDField(source='uuid', read_only=True) 
    
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'password', 'confirm_password']
        read_only_fields = ['id']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({'email': 'Email already exists'})
        
        return attrs
    
    def generate_unique_username(self, first_name, last_name, email):
        """Generate a unique username from name or email"""
        # Try name-based username first
        base_username = f"{first_name.lower()}{last_name.lower()}".replace(' ', '')
        
        # Clean username (remove special characters)
        base_username = re.sub(r'[^a-zA-Z0-9]', '', base_username)
        
        # If name-based username is too short, use email prefix
        if len(base_username) < 3:
            base_username = email.split('@')[0].lower()
            base_username = re.sub(r'[^a-zA-Z0-9]', '', base_username)
        
        # Ensure it's not too long
        base_username = base_username[:20]
        
        # Check if username exists and make it unique
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            # Add random numbers if username exists
            random_suffix = ''.join(random.choices(string.digits, k=3))
            username = f"{base_username}{random_suffix}"
            counter += 1
            if counter > 10:  # Fallback to completely random
                username = f"user_{random.randint(100000, 999999)}"
                break
        
        return username
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        
        # Generate unique username
        username = self.generate_unique_username(
            validated_data['first_name'],
            validated_data['last_name'],
            validated_data['email']
        )
        
        return User.objects.create_user(
            username=username,
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    remember_device = serializers.BooleanField(default=False, required=False)


class ProfileCompletionSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone', 'country', 'state', 'account_type']
    
    def validate_phone(self, value):
        if value and not value.replace('+', '').replace('-', '').replace(' ', '').isdigit():
            raise serializers.ValidationError("Invalid phone number format")
        return value


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'phone', 'country', 'state', 'account_type']  
    
    def validate_username(self, value):
        """Validate username is unique (excluding current user)"""
        if value:
            # Clean username
            value = re.sub(r'[^a-zA-Z0-9_]', '', value.lower())
            
            # Check length
            if len(value) < 3:
                raise serializers.ValidationError("Username must be at least 3 characters long")
            
            if len(value) > 30:
                raise serializers.ValidationError("Username must be less than 30 characters")
            
            # Check uniqueness (exclude current user)
            if self.instance:
                if User.objects.filter(username=value).exclude(id=self.instance.id).exists():
                    raise serializers.ValidationError("Username already exists")
            else:
                if User.objects.filter(username=value).exists():
                    raise serializers.ValidationError("Username already exists")
        
        return value
    
    def validate_phone(self, value):
        if value and not value.replace('+', '').replace('-', '').replace(' ', '').isdigit():
            raise serializers.ValidationError("Invalid phone number format")
        return value


class PasswordResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs


class TwoFactorAuthSerializer(serializers.Serializer):
    otp_token = serializers.CharField(max_length=6, min_length=6)


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    profile_completed = serializers.SerializerMethodField()
    id = serializers.UUIDField(source='uuid', read_only=True)  
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'phone', 'country', 'state', 'account_type', 'is_email_verified',
            'date_joined', 'profile_completed'
        ]
        read_only_fields = ['id', 'date_joined', 'full_name', 'profile_completed']
    
    def get_profile_completed(self, obj):
        return bool(obj.first_name and obj.last_name)
    

class GoogleAuthSerializer(serializers.Serializer):
    """Serializer for Google authentication"""
    id_token = serializers.CharField(
        max_length=2048,
        help_text="Google ID token from Google Sign-In"
    )
    
    def validate_id_token(self, value):
        """Validate the ID token format"""
        if not value or len(value.strip()) == 0:
            raise serializers.ValidationError("ID token is required")
        
        parts = value.split('.')
        if len(parts) != 3:
            raise serializers.ValidationError("Invalid ID token format")
        
        return value.strip()


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()
    uid = serializers.CharField()


class TwoFactorDisableSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)


class ForgetDeviceSerializer(serializers.Serializer):
    device_id = serializers.CharField()


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=False)