#!/usr/bin/env python3
"""
Protocol Coverage Reporting Tool

Analyzes configuration files and generates reports on protocol distribution,
coverage statistics, and validation status.
"""

import json
import sys
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class ProtocolCoverageAnalyzer:
    """Analyzes protocol coverage in proxy configurations"""

    SUPPORTED_PROTOCOLS = {"vmess", "vless", "trojan", "ss", "ssr", "reality", "xhttp"}

    def __init__(self, config_files):
        self.config_files = config_files
        self.configs = []
        self.protocol_stats = defaultdict(int)
        self.validation_results = {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "warnings": [],
        }

    def analyze_configs(self):
        """Analyze all configuration files"""
        for config_file in self.config_files:
            try:
                if config_file.endswith(".json"):
                    self._load_json_config(config_file)
                elif config_file.endswith(".go"):
                    self._parse_go_config(config_file)
                else:
                    self._parse_text_config(config_file)
            except Exception as e:
                self.validation_results["warnings"].append(
                    f"Error processing {config_file}: {str(e)}"
                )

    def _load_json_config(self, filepath):
        """Load JSON config file"""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            if isinstance(data, list):
                self.configs.extend(data)
            else:
                self.configs.append(data)
        except Exception as e:
            self.validation_results["warnings"].append(
                f"Failed to load JSON {filepath}: {str(e)}"
            )

    def _parse_go_config(self, filepath):
        """Parse Go source file for Config structs"""
        try:
            with open(filepath, "r") as f:
                content = f.read()

            # Look for Protocol fields in Go code
            import re

            # Find all Protocol = "xyz" assignments
            protocol_pattern = r'Protocol:\s*"([^"]+)"'
            matches = re.findall(protocol_pattern, content)

            for match in matches:
                if match.lower() in self.SUPPORTED_PROTOCOLS:
                    self.protocol_stats[match.lower()] += 1
        except Exception as e:
            self.validation_results["warnings"].append(
                f"Failed to parse Go config {filepath}: {str(e)}"
            )

    def _parse_text_config(self, filepath):
        """Parse text-based config file (subscription lists)"""
        try:
            with open(filepath, "r") as f:
                content = f.read()

            # Count protocol occurrences
            for protocol in self.SUPPORTED_PROTOCOLS:
                count = content.count(f"{protocol}://")
                if count > 0:
                    self.protocol_stats[protocol] += count
        except Exception as e:
            self.validation_results["warnings"].append(
                f"Failed to parse text config {filepath}: {str(e)}"
            )

    def validate_protocols(self):
        """Validate protocol usage"""
        self.validation_results["total"] = len(self.configs)

        for config in self.configs:
            is_valid = True
            issues = []

            # Check protocol field
            protocol = None
            if isinstance(config, dict):
                protocol = config.get("Protocol") or config.get("protocol")

            if not protocol:
                is_valid = False
                issues.append("Missing protocol field")
            elif str(protocol).lower() not in self.SUPPORTED_PROTOCOLS:
                is_valid = False
                issues.append(f"Unsupported protocol: {protocol}")

            # Validate required fields based on protocol
            if protocol:
                self._validate_protocol_fields(config, str(protocol).lower(), issues)

            if is_valid:
                self.validation_results["valid"] += 1
                protocol_str = str(protocol).lower() if protocol else "unknown"
                self.protocol_stats[protocol_str] += 1
            else:
                self.validation_results["invalid"] += 1
                self.validation_results["warnings"].extend(
                    [f"Config validation issues: {', '.join(issues)}"]
                )

    def _validate_protocol_fields(self, config, protocol, issues):
        """Validate required fields for each protocol"""
        if not isinstance(config, dict):
            return

        required_fields = {
            "vmess": ["UUID", "Server", "Port"],
            "vless": ["UUID", "Server", "Port"],
            "trojan": ["Password", "Server", "Port"],
            "ss": ["Password", "Cipher", "Server", "Port"],
            "ssr": ["Password", "Cipher", "Server", "Port"],
            "reality": ["PublicKey", "ShortID", "Server", "Port"],
            "xhttp": ["HTTPMethod", "HTTPHost", "Server", "Port"],
        }

        if protocol in required_fields:
            for field in required_fields[protocol]:
                if not config.get(field):
                    issues.append(f"Missing required field: {field}")

    def generate_report(self):
        """Generate coverage report"""
        report = {
            "title": "Protocol Coverage Report",
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_configurations": self.validation_results["total"],
                "valid_configurations": self.validation_results["valid"],
                "invalid_configurations": self.validation_results["invalid"],
            },
            "protocol_distribution": dict(self.protocol_stats),
            "protocol_coverage": self._calculate_coverage(),
            "validation_details": self._get_validation_details(),
        }

        return report

    def _calculate_coverage(self):
        """Calculate protocol coverage percentage"""
        if not self.protocol_stats:
            return {}

        total = sum(self.protocol_stats.values())
        coverage = {}

        for protocol in self.SUPPORTED_PROTOCOLS:
            count = self.protocol_stats.get(protocol, 0)
            percentage = (count / total * 100) if total > 0 else 0
            coverage[protocol] = {
                "count": count,
                "percentage": round(percentage, 2),
                "implemented": True,
            }

        return coverage

    def _get_validation_details(self):
        """Get validation details"""
        return {
            "total_checked": self.validation_results["total"],
            "passed": self.validation_results["valid"],
            "failed": self.validation_results["invalid"],
            "success_rate": round(
                (
                    self.validation_results["valid"]
                    / self.validation_results["total"]
                    * 100
                )
                if self.validation_results["total"] > 0
                else 0,
                2,
            ),
            "warnings": len(self.validation_results["warnings"]),
        }

    def print_report(self, report):
        """Print human-readable report"""
        print("\n" + "=" * 70)
        print(f" {report['title']}")
        print(f" Generated: {report['timestamp']}")
        print("=" * 70)

        # Summary section
        print("\n📊 SUMMARY")
        print("-" * 70)
        summary = report["summary"]
        print(f"  Total Configurations:      {summary['total_configurations']}")
        print(f"  Valid Configurations:      {summary['valid_configurations']}")
        print(f"  Invalid Configurations:    {summary['invalid_configurations']}")

        # Protocol Coverage
        print("\n🔗 PROTOCOL COVERAGE")
        print("-" * 70)
        coverage = report["protocol_coverage"]

        if coverage:
            # Sort by count descending
            sorted_protocols = sorted(
                coverage.items(), key=lambda x: x[1]["count"], reverse=True
            )

            for protocol, stats in sorted_protocols:
                bar_length = 30
                filled = int((stats["percentage"] / 100) * bar_length)
                bar = "█" * filled + "░" * (bar_length - filled)
                print(
                    f"  {protocol.upper():12} {bar} {stats['count']:6} ({stats['percentage']:5.1f}%)"
                )

            total_coverage = sum(1 for _, stats in coverage.items() if stats["count"] > 0)
            print(f"\n  Protocols Implemented: {total_coverage}/{len(self.SUPPORTED_PROTOCOLS)}")
        else:
            print("  No protocol data available")

        # Validation Results
        print("\n✓ VALIDATION RESULTS")
        print("-" * 70)
        validation = report["validation_details"]
        print(f"  Checked:        {validation['total_checked']}")
        print(f"  Passed:         {validation['passed']}")
        print(f"  Failed:         {validation['failed']}")
        print(f"  Success Rate:   {validation['success_rate']}%")

        # Warnings
        if self.validation_results["warnings"]:
            print("\n⚠️  WARNINGS")
            print("-" * 70)
            for warning in self.validation_results["warnings"][:10]:  # Show first 10
                print(f"  • {warning}")

            if len(self.validation_results["warnings"]) > 10:
                print(
                    f"  ... and {len(self.validation_results['warnings']) - 10} more warnings"
                )

        print("\n" + "=" * 70 + "\n")

    def export_json(self, filepath):
        """Export report to JSON"""
        report = self.generate_report()
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report exported to {filepath}")

    def export_csv(self, filepath):
        """Export report to CSV"""
        report = self.generate_report()
        with open(filepath, "w") as f:
            f.write("Protocol,Count,Percentage\n")
            for protocol, stats in report["protocol_coverage"].items():
                f.write(f"{protocol},{stats['count']},{stats['percentage']}\n")
        print(f"CSV report exported to {filepath}")


def find_config_files(directory="."):
    """Find all config files in a directory"""
    config_files = []
    extensions = {"*.json", "*.go", "*.txt", "*.yaml", "*.yml"}

    for ext in extensions:
        config_files.extend(Path(directory).glob(f"**/{ext}"))

    return [str(f) for f in config_files]


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Protocol Coverage Analysis Tool"
    )
    parser.add_argument(
        "config_files",
        nargs="*",
        help="Config files to analyze (auto-discovers if not specified)",
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=".",
        help="Directory to scan for config files",
    )
    parser.add_argument(
        "--json-output", help="Export report to JSON file"
    )
    parser.add_argument(
        "--csv-output", help="Export report to CSV file"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress console output"
    )

    args = parser.parse_args()

    # Determine config files
    if args.config_files:
        config_files = args.config_files
    else:
        config_files = find_config_files(args.directory)
        print(f"Found {len(config_files)} config files to analyze")

    if not config_files:
        print("No configuration files found")
        sys.exit(1)

    # Run analysis
    analyzer = ProtocolCoverageAnalyzer(config_files)
    analyzer.analyze_configs()
    analyzer.validate_protocols()

    # Generate and print report
    report = analyzer.generate_report()

    if not args.quiet:
        analyzer.print_report(report)

    # Export if requested
    if args.json_output:
        analyzer.export_json(args.json_output)

    if args.csv_output:
        analyzer.export_csv(args.csv_output)

    # Exit with appropriate code
    if analyzer.validation_results["invalid"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
