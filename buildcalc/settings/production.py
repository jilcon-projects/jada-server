"""
Django production settings for buildcalc project.
"""

from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=lambda v: [s.strip() for s in v.split(',')])

# Database - PostgreSQL for production
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT', default='5432'),
    }
}


# CORS settings - restrictive for production
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    'https://buildestimate.ai',
    'http://localhost:8000'
]

CORS_ALLOW_CREDENTIALS = True

# Brevo API settings - Production
BREVO_API_KEY = config('BREVO_API_KEY')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')
DEFAULT_FROM_NAME = config('DEFAULT_FROM_NAME')

# Email backend - still using Django's email backend but with Brevo SMTP settings if needed
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# WhiteNoise static files configuration
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Cache settings 
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Security settings for production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# WhiteNoise settings
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = False  


# Google OAuth2 Settings
GOOGLE_OAUTH2_CLIENT_ID = config('GOOGLE_OAUTH2_CLIENT_ID', default='')
GOOGLE_OAUTH2_CLIENT_SECRET = config('GOOGLE_OAUTH2_CLIENT_SECRET', default='')

APPEND_SLASH = False



