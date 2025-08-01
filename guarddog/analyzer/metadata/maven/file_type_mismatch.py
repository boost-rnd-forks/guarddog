""" File Type Mismatch Detector for Maven

Detects files with extensions that don't match their actual content type
"""
import os
from typing import Dict

from guarddog.analyzer.metadata.file_type_mismatch import FileTypeMismatchDetector


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
        self.description = "Detects Maven package files with misleading extensions that don't match their actual content type"
    
    def get_package_files(self, package_info: dict, path: str) -> Dict[str, str]:
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
        decompressed_path = package_info.get("path", {}).get("decompressed_path")
        
        if decompressed_path and os.path.exists(decompressed_path):
            # Analyze decompressed JAR contents
            base_path = decompressed_path
        else:
            # Fall back to the main package path
            base_path = path
        
        # Walk through all files in the package
        for root, dirs, files in os.walk(base_path):
            for file_name in files:
                absolute_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(absolute_path, base_path)
                
                # Skip Maven-specific files that are expected to have certain formats
                if self._should_skip_maven_file(relative_path):
                    continue
                
                package_files[relative_path] = absolute_path
        
        return package_files
    
    @staticmethod
    def _should_skip_maven_file(relative_path: str) -> bool:
        """
        Check if a file should be skipped from analysis (Maven-specific logic).
        
        Args:
            relative_path (str): Relative path of the file
            
        Returns:
            bool: True if the file should be skipped
        """
        # Skip META-INF directory files (they have specific formats)
        if relative_path.startswith('META-INF/'):
            return True
        
        # Skip Maven build artifacts
        if '/target/' in relative_path or relative_path.startswith('target/'):
            return True
        
        # Skip common Maven files that have expected formats
        maven_files = {
            'pom.xml',
            'maven-metadata.xml',
            'pom.properties',
            '.maven-metadata.xml',
        }
        
        file_name = os.path.basename(relative_path)
        if file_name in maven_files:
            return True
        
        # Skip checksums and signatures
        if file_name.endswith(('.md5', '.sha1', '.sha256', '.sha512', '.asc', '.sig')):
            return True
        
        return False