""" Release Zero Detector

Detects when a package has its latest release version to 0.0.0
"""
import logging
from typing import Optional

from guarddog.analyzer.metadata.release_zero import ReleaseZeroDetector

log = logging.getLogger("guarddog")


class MavenReleaseZeroDetector(ReleaseZeroDetector):
    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        """
        Detects if a Maven package's latest version is 0.0.0 or 0.0
        
        Args:
            package_info: Maven package metadata
            path: Optional path to package
            name: Optional package name
            version: Optional package version
            
        Returns:
            tuple[bool, str]: (True if version is 0, message with details)
        """
        log.debug(f"Running zero version heuristic on Maven package {name} version {version}")

        latest_version = package_info.get("version", "")

        return (latest_version in ["0.0.0", "0.0"],
                ReleaseZeroDetector.MESSAGE_TEMPLATE % latest_version)
