# managers.py  
import re
import random
import string
from django.contrib.auth.models import BaseUserManager


class CustomUserManager(BaseUserManager):
    """Custom user manager for User model with email as username field"""
    
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
        while self.filter(username=username).exists():
            # Add random numbers if username exists
            random_suffix = ''.join(random.choices(string.digits, k=3))
            username = f"{base_username}{random_suffix}"
            counter += 1
            if counter > 10:  # Fallback to completely random
                username = f"user_{random.randint(100000, 999999)}"
                break
        
        return username
    
    def create_user(self, email, first_name, last_name, password=None, username=None, **extra_fields):
        """Create and return a regular user with an email and password"""
        if not email:
            raise ValueError('The Email field must be set')
        if not first_name:
            raise ValueError('The First Name field must be set')
        if not last_name:
            raise ValueError('The Last Name field must be set')
        
        email = self.normalize_email(email)
        
        # Generate username if not provided
        if not username:
            username = self.generate_unique_username(first_name, last_name, email)
        
        # Set default values
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        
        user = self.model(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            **extra_fields
        )
        
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, first_name, last_name, password=None, **extra_fields):
        """Create and return a superuser with an email and password"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        # Generate username for superuser
        username = self.generate_unique_username(first_name, last_name, email)
        
        return self.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            password=password,
            **extra_fields
        )