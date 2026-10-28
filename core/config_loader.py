import yaml
import os
from core.logger import setup_logger

logger = setup_logger(__name__)

class ConfigLoader:
    @staticmethod
    def load(config_path: str = "config/settings.yaml") -> dict:
        if not os.path.exists(config_path):
            logger.error(f"Configuration file not found: {config_path}")
            return {}
            
        with open(config_path, "r") as file:
            try:
                config = yaml.safe_load(file)
                logger.info(f"Loaded configuration from {config_path}")
                return config
            except yaml.YAMLError as exc:
                logger.error(f"Error parsing YAML config: {exc}")
                return {}
