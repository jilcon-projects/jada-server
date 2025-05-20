"""
Django development settings for buildcalc project.
"""

from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# # Database - PostgreSQL for development
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

# Database - SQLite for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# CORS settings - permissive for development
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# Brevo API settings - Development
BREVO_API_KEY = config('BREVO_API_KEY')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')
DEFAULT_FROM_NAME = config('DEFAULT_FROM_NAME')

# Email - Development settings (console backend for development)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# # Add Django Debug Toolbar if installed
# try:
#     import debug_toolbar
#     INSTALLED_APPS += ['debug_toolbar']
#     MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
#     INTERNAL_IPS = ['127.0.0.1']
# except ImportError:
#     pass