from .development import DevelopmentConfig 
from .production import ProductionConfig
from config.common import ENVIRONMENT
from .staging import StagingConfig
from .test import TestConfig 


configs = {
  'development': DevelopmentConfig,
  'production': ProductionConfig,
  'staging': StagingConfig,
  'test': TestConfig
}

config = configs[ENVIRONMENT]()