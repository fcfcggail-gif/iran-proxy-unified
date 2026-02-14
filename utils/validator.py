#!/usr/bin/env python3
"""
Configuration validator for iran-proxy-unified
Validates sources, rules, and obfuscation configurations
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
import sys


class ConfigValidator:
    """Validates project configuration files"""

    def __init__(self):
        self.errors = []
        self.warnings = []

    def validate_sources(self, sources_file: Path) -> bool:
        """Validate sources.yaml configuration"""
        try:
            with open(sources_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if not config or 'sources' not in config:
                self.errors.append("sources.yaml must contain 'sources' key")
                return False

            sources = config['sources']
            if not isinstance(sources, list):
                self.errors.append("sources must be a list")
                return False

            for i, source in enumerate(sources):
                if not isinstance(source, dict):
                    self.errors.append(f"Source {i} must be a dictionary")
                    continue

                # Check required fields
                required = ['name', 'url', 'type', 'enabled']
                for field in required:
                    if field not in source:
                        self.errors.append(f"Source {i} missing required field: {field}")

                # Validate type
                if source.get('type') not in ['base64', 'json', 'plain']:
                    self.errors.append(f"Source {i} has invalid type: {source.get('type')}")

            return len(self.errors) == 0

        except yaml.YAMLError as e:
            self.errors.append(f"YAML parse error in sources.yaml: {e}")
            return False
        except Exception as e:
            self.errors.append(f"Error validating sources.yaml: {e}")
            return False

    def validate_rules(self, rules_file: Path) -> bool:
        """Validate iran_rules.json configuration"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)

            if not isinstance(rules, list):
                self.errors.append("iran_rules.json must be a list")
                return False

            for i, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    self.errors.append(f"Rule {i} must be a dictionary")
                    continue

                # Check required fields
                required = ['name', 'type', 'pattern', 'action', 'enabled']
                for field in required:
                    if field not in rule:
                        self.errors.append(f"Rule {i} missing required field: {field}")

                # Validate type
                if rule.get('type') not in ['protocol', 'country', 'domain']:
                    self.errors.append(f"Rule {i} has invalid type: {rule.get('type')}")

                # Validate action
                if rule.get('action') not in ['include', 'exclude']:
                    self.errors.append(f"Rule {i} has invalid action: {rule.get('action')}")

            return len(self.errors) == 0

        except json.JSONDecodeError as e:
            self.errors.append(f"JSON parse error in iran_rules.json: {e}")
            return False
        except Exception as e:
            self.errors.append(f"Error validating iran_rules.json: {e}")
            return False

    def validate_obfuscation(self, obfuscation_file: Path) -> bool:
        """Validate obfuscation_rules.yaml configuration"""
        try:
            with open(obfuscation_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if not config:
                self.errors.append("obfuscation_rules.yaml is empty")
                return False

            if 'obfuscation_strategies' not in config:
                self.warnings.append("obfuscation_rules.yaml missing 'obfuscation_strategies'")

            return True

        except yaml.YAMLError as e:
            self.errors.append(f"YAML parse error in obfuscation_rules.yaml: {e}")
            return False
        except Exception as e:
            self.errors.append(f"Error validating obfuscation_rules.yaml: {e}")
            return False

    def validate_all(self, config_dir: Path) -> bool:
        """Validate all configuration files in config directory"""
        all_valid = True

        all_valid &= self.validate_sources(config_dir / 'sources.yaml')
        all_valid &= self.validate_rules(config_dir / 'iran_rules.json')
        all_valid &= self.validate_obfuscation(config_dir / 'obfuscation_rules.yaml')

        return all_valid

    def print_report(self) -> None:
        """Print validation report"""
        if self.errors:
            print("❌ ERRORS:")
            for error in self.errors:
                print(f"  - {error}")

        if self.warnings:
            print("⚠️  WARNINGS:")
            for warning in self.warnings:
                print(f"  - {warning}")

        if not self.errors and not self.warnings:
            print("✅ All configurations valid!")


def main():
    """Validate configurations"""
    config_dir = Path(__file__).parent.parent / 'config'

    validator = ConfigValidator()
    valid = validator.validate_all(config_dir)

    validator.print_report()

    sys.exit(0 if valid else 1)


if __name__ == '__main__':
    main()
