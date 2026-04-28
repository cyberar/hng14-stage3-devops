# ============================================================
# config_loader.py — Loads and validates config.yaml
# A single shared function so every module reads the same config object.
# ============================================================

import yaml          # PyYAML — parses .yaml files into Python dicts
import os
import sys
import re


def resolve_env_vars(cfg: dict) -> dict:
    """
    Walk through the config dict and replace any "${VAR_NAME}"
    string with the actual environment variable value.
    """
    for section, values in cfg.items():
        if isinstance(values, dict):
            for key, value in values.items():
                if isinstance(value, str):
                    # Find ${VARIABLE_NAME} patterns and replace them
                    matches = re.findall(r'\$\{([^}]+)\}', value)
                    for var_name in matches:
                        env_value = os.environ.get(var_name)
                        if env_value:
                            cfg[section][key] = value.replace(
                                f'${{{var_name}}}', env_value
                            )
                        else:
                            print(f"[WARN] Environment variable {var_name} not set")
    return cfg


def load_config(path: str = None) -> dict:
    """
    Load configuration from config.yaml.
    Searches for the config file in:
      1. The explicitly passed `path`
      2. Same directory as this script
      3. /etc/detector/config.yaml (production default)
    Returns the config as a plain Python dictionary.
    """

    # 1. Build list of each config file candidate
    candidates = []
    if path:
        candidates.append(path)                                      # explicit override

    # Directory where THIS file lives (detector/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(script_dir, "config.yaml"))      # detector/config.yaml
    candidates.append("/etc/detector/config.yaml")                   # system-wide fallback

    # 2. Try each candidate in order
    for candidate in candidates:
        if os.path.exists(candidate):
            with open(candidate, "r") as f:
                cfg = yaml.safe_load(f)   # safe_load prevents arbitrary code execution
                cfg = resolve_env_vars(cfg)
            _validate(cfg)                # blow up early if critical keys are missing
            return cfg

    # 3. Nothing found — abort with a clear message
    print(f"[ERROR] config.yaml not found. Tried: {candidates}", file=sys.stderr)
    sys.exit(1)


def _validate(cfg: dict):
    """
    Minimal validation: ensure the top-level sections we depend on exist.
    Raises KeyError with a helpful message if something is missing.
    """
    required_sections = ["log", "sliding_window", "baseline", "detection",
                         "blocking", "slack", "dashboard", "audit"]
    for section in required_sections:
        if section not in cfg:
            raise KeyError(
                f"Missing required config section: '{section}'. "
                f"Check your config.yaml."
            )