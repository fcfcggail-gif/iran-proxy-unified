#!/usr/bin/env python3
"""
GitHub Actions helper for iran-proxy-unified
Orchestrates automatic config updates and subscription generation
"""

import os
import subprocess
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional
import base64


logger = logging.getLogger(__name__)


class GitHubActionsHelper:
    """Helper for GitHub Actions workflow integration"""

    def __init__(self, repo_dir: Path = None):
        self.repo_dir = repo_dir or Path.cwd()
        self.git_user = os.environ.get('GIT_USER', 'GitHub Actions')
        self.git_email = os.environ.get('GIT_EMAIL', 'actions@github.com')
        self.github_token = os.environ.get('GITHUB_TOKEN', '')

    def configure_git(self) -> bool:
        """Configure git for automated commits"""
        try:
            subprocess.run(['git', 'config', '--global', 'user.name', self.git_user], check=True)
            subprocess.run(['git', 'config', '--global', 'user.email', self.git_email], check=True)
            logger.info("Git configured successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure git: {e}")
            return False

    def add_files(self, patterns: list) -> bool:
        """Add files to git staging"""
        try:
            for pattern in patterns:
                subprocess.run(['git', 'add', pattern], cwd=self.repo_dir, check=True)
            logger.info(f"Added {len(patterns)} file patterns")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add files: {e}")
            return False

    def commit(self, message: str) -> bool:
        """Commit changes"""
        try:
            subprocess.run(
                ['git', 'commit', '-m', message],
                cwd=self.repo_dir,
                check=True
            )
            logger.info(f"Committed: {message}")
            return True
        except subprocess.CalledProcessError as e:
            logger.warning(f"Nothing to commit: {e}")
            return False

    def push(self) -> bool:
        """Push changes to remote"""
        try:
            # Setup authentication if token available
            if self.github_token:
                remote_url = f"https://x-access-token:{self.github_token}@github.com/{self._get_repo_name()}.git"
                subprocess.run(['git', 'remote', 'set-url', 'origin', remote_url], cwd=self.repo_dir)

            subprocess.run(['git', 'push', 'origin', 'main'], cwd=self.repo_dir, check=True)
            logger.info("Pushed changes to remote")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to push: {e}")
            return False

    def execute_step(self, step_name: str, command: list, use_shell: bool = False) -> bool:
        """Execute a workflow step"""
        try:
            logger.info(f"Executing step: {step_name}")
            if use_shell:
                subprocess.run(' '.join(command), shell=True, cwd=self.repo_dir, check=True)
            else:
                subprocess.run(command, cwd=self.repo_dir, check=True)
            logger.info(f"✅ Step completed: {step_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Step failed: {step_name} - {e}")
            return False

    def generate_summary(self, summary_file: Path, content: str) -> None:
        """Generate GitHub Actions workflow summary"""
        try:
            with open(summary_file, 'a') as f:
                f.write(content + '\n')
            logger.info(f"Updated summary: {summary_file}")
        except Exception as e:
            logger.error(f"Failed to update summary: {e}")

    def set_output(self, name: str, value: str) -> None:
        """Set GitHub Actions output variable"""
        output_file = os.environ.get('GITHUB_OUTPUT')
        if output_file:
            try:
                with open(output_file, 'a') as f:
                    f.write(f"{name}={value}\n")
                logger.info(f"Set output: {name}={value}")
            except Exception as e:
                logger.error(f"Failed to set output: {e}")

    def _get_repo_name(self) -> Optional[str]:
        """Get GitHub repository name from environment"""
        try:
            result = subprocess.run(
                ['git', 'config', '--get', 'remote.origin.url'],
                cwd=self.repo_dir,
                capture_output=True,
                text=True,
                check=True
            )
            url = result.stdout.strip()
            # Extract repo name from URL
            if 'github.com' in url:
                return url.split('/')[-1].replace('.git', '')
        except Exception:
            pass
        return None

    def run_full_workflow(self) -> bool:
        """Execute full update workflow"""
        logger.info("Starting full workflow...")

        steps = [
            ("Configure Git", ['git', 'config', '--global', 'user.name', self.git_user]),
            ("Fetch Configs", ['./core/aggregator', '-mode=fetch']),
            ("Generate Clash", ['./core/aggregator', '-mode=generate', '-format=clash']),
            ("Generate Singbox", ['./core/aggregator', '-mode=generate', '-format=singbox']),
        ]

        success_count = 0
        for step_name, command in steps:
            if self.execute_step(step_name, command):
                success_count += 1

        logger.info(f"Workflow completed: {success_count}/{len(steps)} steps succeeded")
        return success_count == len(steps)


def main():
    """Execute GitHub Actions workflow"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    helper = GitHubActionsHelper()

    # Configure git
    helper.configure_git()

    # Execute workflow
    success = helper.run_full_workflow()

    # Generate summary
    summary = {
        'status': 'success' if success else 'failed',
        'timestamp': datetime.now().isoformat(),
        'message': 'Workflow completed successfully' if success else 'Workflow encountered errors'
    }

    summary_file = Path(os.environ.get('GITHUB_STEP_SUMMARY', '/tmp/summary.md'))
    helper.generate_summary(summary_file, json.dumps(summary, indent=2))

    return 0 if success else 1


if __name__ == '__main__':
    exit(main())
