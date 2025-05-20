from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from ..models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({'email': 'Email already exists'})
        
        if User.objects.filter(username=attrs['username']).exists():
            raise serializers.ValidationError({'username': 'Username already exists'})
        
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        return User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
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
        fields = ['email', 'first_name', 'last_name', 'phone', 'country', 'state', 'account_type']
    
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


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()
    uid = serializers.CharField()


class TwoFactorDisableSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)


class ForgetDeviceSerializer(serializers.Serializer):
    device_id = serializers.CharField()


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=False)