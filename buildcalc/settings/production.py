"""
Django production settings for buildcalc project.
"""

from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=lambda v: [s.strip() for s in v.split(',')])

# Database - Currently using SQLite, but should be changed to PostgreSQL or similar for production
# TODO: Migrate to a production-grade database before deployment

# # Database - PostgreSQL for production
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': config('DB_NAME'),
#         'USER': config('DB_USER'),
#         'PASSWORD': config('DB_PASSWORD'),
#         'HOST': config('DB_HOST', default='localhost'),
#         'PORT': config('DB_PORT', default='5432'),
#     }
# }


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'ATOMIC_REQUESTS': True,
        'CONN_MAX_AGE': 600,  # Keep connections alive for 10 minutes
    }
}

# CORS settings - restrictive for production
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS', 
    cast=lambda v: [s.strip() for s in v.split(',')]
)
CORS_ALLOW_CREDENTIALS = True

# Brevo API settings - Production
BREVO_API_KEY = config('BREVO_API_KEY')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')
DEFAULT_FROM_NAME = config('DEFAULT_FROM_NAME')

# Email backend - still using Django's email backend but with Brevo SMTP settings if needed
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Security settings
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Optimize static file serving
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Cache settings - consider adding Redis or Memcached
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}