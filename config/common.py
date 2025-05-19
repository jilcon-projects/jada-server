from dataclasses import dataclass, field
from typing import List
import os


ENVIRONMENT = os.getenv('FLASK_ENV', 'development')

IS_DEVELOPMENT: bool = ENVIRONMENT == 'development'
IS_PRODUCTION: bool = ENVIRONMENT == 'production'
IS_STAGING: bool = ENVIRONMENT == 'staging'
IS_TEST: bool = ENVIRONMENT == 'test'
PORT = int(os.getenv('PORT', 9080))

CACHE = {
  'CACHE_TYPE': 'SimpleCache',
  'CACHE_DEFAULT_TIMEOUT': 60,
  'DEBUG': IS_DEVELOPMENT,
}

@dataclass
class Config():
  CORS_ORIGIN: List[str] = field(default_factory=lambda: os.getenv('CORS_ORIGIN', '').split() or [])
  AUTH_SECRET_KEY: bytes = os.urandom(32)
  FLASK_DEBUG: bool = IS_DEVELOPMENT
  AUTH_TOKEN_DURATION: int = 3600