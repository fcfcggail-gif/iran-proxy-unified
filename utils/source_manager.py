#!/usr/bin/env python3
"""
Source manager for iran-proxy-unified
Manages proxy configuration sources and updates
"""

import yaml
import json
import asyncio
import aiohttp
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import base64


logger = logging.getLogger(__name__)


class ConfigSource:
    """Represents a proxy configuration source"""

    def __init__(self, name: str, url: str, source_type: str, enabled: bool = True,
                 timeout: int = 30, interval: int = 360):
        self.name = name
        self.url = url
        self.type = source_type
        self.enabled = enabled
        self.timeout = timeout
        self.interval = interval
        self.last_updated = None
        self.config_count = 0

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'url': self.url,
            'type': self.type,
            'enabled': self.enabled,
            'timeout': self.timeout,
            'interval': self.interval,
        }


class SourceManager:
    """Manages proxy configuration sources"""

    def __init__(self, sources_file: Path):
        self.sources_file = sources_file
        self.sources: List[ConfigSource] = []
        self.load_sources()

    def load_sources(self) -> None:
        """Load sources from configuration file"""
        try:
            with open(self.sources_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if not config or 'sources' not in config:
                logger.warning("No sources found in configuration")
                return

            for source_config in config['sources']:
                source = ConfigSource(
                    name=source_config['name'],
                    url=source_config['url'],
                    source_type=source_config['type'],
                    enabled=source_config.get('enabled', True),
                    timeout=source_config.get('timeout', 30),
                    interval=source_config.get('interval', 360),
                )
                self.sources.append(source)

            logger.info(f"Loaded {len(self.sources)} sources")

        except Exception as e:
            logger.error(f"Error loading sources: {e}")

    def save_sources(self) -> None:
        """Save sources to configuration file"""
        try:
            config = {
                'sources': [source.to_dict() for source in self.sources]
            }

            with open(self.sources_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False)

            logger.info(f"Saved {len(self.sources)} sources")

        except Exception as e:
            logger.error(f"Error saving sources: {e}")

    def add_source(self, name: str, url: str, source_type: str,
                   enabled: bool = True, timeout: int = 30, interval: int = 360) -> None:
        """Add a new source"""
        source = ConfigSource(name, url, source_type, enabled, timeout, interval)
        self.sources.append(source)
        logger.info(f"Added source: {name}")

    def remove_source(self, name: str) -> None:
        """Remove a source by name"""
        self.sources = [s for s in self.sources if s.name != name]
        logger.info(f"Removed source: {name}")

    def get_source(self, name: str) -> Optional[ConfigSource]:
        """Get a source by name"""
        for source in self.sources:
            if source.name == name:
                return source
        return None

    def get_enabled_sources(self) -> List[ConfigSource]:
        """Get all enabled sources"""
        return [s for s in self.sources if s.enabled]

    async def fetch_from_source(self, source: ConfigSource) -> Optional[List[str]]:
        """Fetch configurations from a single source"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(source.url, timeout=source.timeout) as response:
                    if response.status != 200:
                        logger.warning(f"Failed to fetch from {source.name}: HTTP {response.status}")
                        return None

                    content = await response.text()

                    # Parse based on source type
                    if source.type == 'base64':
                        content = base64.b64decode(content).decode('utf-8')

                    # Split by newlines to get individual configs
                    configs = [line.strip() for line in content.split('\n') if line.strip()]

                    source.config_count = len(configs)
                    source.last_updated = datetime.now()

                    logger.info(f"Fetched {len(configs)} configs from {source.name}")
                    return configs

        except asyncio.TimeoutError:
            logger.error(f"Timeout fetching from {source.name}")
            return None
        except Exception as e:
            logger.error(f"Error fetching from {source.name}: {e}")
            return None

    async def fetch_all_sources(self) -> Dict[str, List[str]]:
        """Fetch configurations from all enabled sources"""
        results = {}
        sources = self.get_enabled_sources()

        tasks = [self.fetch_from_source(source) for source in sources]
        responses = await asyncio.gather(*tasks)

        for source, configs in zip(sources, responses):
            if configs:
                results[source.name] = configs

        logger.info(f"Fetched configs from {len(results)}/{len(sources)} sources")
        return results

    def get_source_status(self) -> Dict:
        """Get status of all sources"""
        status = {
            'total_sources': len(self.sources),
            'enabled_sources': len(self.get_enabled_sources()),
            'sources': []
        }

        for source in self.sources:
            status['sources'].append({
                'name': source.name,
                'url': source.url,
                'enabled': source.enabled,
                'last_updated': source.last_updated.isoformat() if source.last_updated else None,
                'config_count': source.config_count,
            })

        return status


def main():
    """Example usage"""
    logging.basicConfig(level=logging.INFO)

    config_dir = Path(__file__).parent.parent / 'config'
    manager = SourceManager(config_dir / 'sources.yaml')

    # Print source status
    status = manager.get_source_status()
    print(json.dumps(status, indent=2))


if __name__ == '__main__':
    main()
