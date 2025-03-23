from dataclasses import dataclass
from .common import Config


@dataclass
class StagingConfig(Config):
  # List out dev specific configs here
  SOME_DUMMY_CONFIG_KEY: str = ''