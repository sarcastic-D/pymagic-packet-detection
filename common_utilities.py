import yaml
import os

def load_config(config_path="config.yaml"):
    """
    Loads the YAML configuration file.
    """
    if not os.path.exists(config_path):
        return {
            "OUTPUT_DIR": "output_v2", 
            "SCORING_WEIGHTS": {}, 
            "MATCH_SCORE_THRESHOLD": 50
        }
    
    with open(config_path, "r") as f:
        return yaml.safe_load(f)