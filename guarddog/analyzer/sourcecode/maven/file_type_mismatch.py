"""File Type Mismatch Detector for Maven

Detects files with extensions that don't match their actual content type
"""

import os
from typing import Dict
import logging

from guarddog.analyzer.sourcecode.file_type_mismatch import FileTypeMismatchDetector

log = logging.getLogger("guarddog")


class MavenFileTypeMismatchDetector(FileTypeMismatchDetector):
    """
    Maven-specific file type mismatch detector.

    This detector analyzes Maven packages to find files where the file extension
    doesn't match the actual file content. This can help identify:
    - Executables disguised as text files
    - Binary files with misleading extensions
    - Archives masquerading as configuration files
    - Scripts with incorrect extensions
    """

    def __init__(self):
        super().__init__()
        # Override description to be Maven-specific
        self.description = "Detects Maven package files with misleading extensions that don't match their actual type"

    def get_package_files(self, path: str) -> Dict[str, str]:
        """
        Get all files in the Maven package for analysis.

        Args:
            package_info (dict): Maven package metadata
            path (str): Package path

        Returns:
            Dict[str, str]: Mapping of relative paths to absolute paths
        """
        package_files = {}

        # For Maven packages, we want to analyze the decompressed JAR contents
        # Check if we have a decompressed path from the Maven scanner
        decompressed_path = os.path.join(path, "decompressed")

        if decompressed_path and os.path.exists(decompressed_path):
            # Analyze decompressed JAR contents
            log.debug(f"decompressed dir: {os.listdir(decompressed_path)}")
            base_path = decompressed_path
        else:
            # Fall back to the main package path
            log.warning("could not find decompressed path")
            base_path = path
        log.debug(f"**base path {base_path}")
        # Walk through all files in the package
        for root, dirs, files in os.walk(base_path):
            for file_name in files:
                absolute_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(absolute_path, base_path)
                package_files[relative_path] = absolute_path

        return package_files
