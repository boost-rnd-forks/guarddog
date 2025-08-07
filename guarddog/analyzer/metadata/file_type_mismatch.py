from abc import abstractmethod
from typing import Optional, Dict
import os
import logging

from guarddog.analyzer.metadata.detector import Detector

log = logging.getLogger("guarddog")

# Common file signatures (magic bytes) for detection
FILE_SIGNATURES = {
    # Executables
    b'\x4D\x5A': '.exe',  # PE/DOS executable
    b'\x7FELF': '.elf',   # ELF executable (Linux)
    b'\xFE\xED\xFA\xCE': '.macho',  # Mach-O (macOS)
    b'\xFE\xED\xFA\xCF': '.macho',  # Mach-O 64-bit
    b'\xCA\xFE\xBA\xBE': '.class',  # Mach-O universal binary

    # Archives
    b'PK\x03\x04': '.zip',  # ZIP archive (also JAR, WAR, etc.)
    b'PK\x05\x06': '.zip',  # Empty ZIP
    b'PK\x07\x08': '.zip',  # Spanned ZIP
    b'\x1F\x8B\x08': '.gz',  # GZIP
    b'BZh': '.bz2',  # BZIP2
    b'\x37\x7A\xBC\xAF\x27\x1C': '.7z',  # 7-Zip
    b'Rar!\x1A\x07\x00': '.rar',  # RAR archive
    b'Rar!\x1A\x07\x01\x00': '.rar',  # RAR 5.0+

    # Images
    b'\xFF\xD8\xFF': '.jpg',  # JPEG
    b'\x89PNG\r\n\x1A\n': '.png',  # PNG
    b'GIF87a': '.gif',  # GIF87a
    b'GIF89a': '.gif',  # GIF89a
    b'BM': '.bmp',  # Bitmap
    b'RIFF': '.webp',  # WebP (when followed by WEBP)

    # Documents
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': '.doc',  # MS Office (legacy)
    b'%PDF': '.pdf',  # PDF

    # Scripts and binaries that might be disguised
    b'#!/bin/sh': '.sh',  # Shell script
    b'#!/bin/bash': '.sh',  # Bash script
    b'#!/usr/bin/env python': '.py',  # Python script
    b'#!/usr/bin/env node': '.js',  # Node.js script

    # Other suspicious files
    b'\x00\x00\x01\x00': '.ico',  # Windows icon
    b'\x00\x00\x02\x00': '.cur',  # Windows cursor
}

# File extensions that are commonly safe text/config files
SAFE_TEXT_EXTENSIONS = {
    '.txt', '.md', '.rst', '.json', '.xml', '.yml', '.yaml',
    '.properties', '.cfg', '.conf', '.ini', '.log', '.csv',
    '.java', '.py', '.js', '.ts', '.html', '.css', '.sql',
    '.sh', '.bat', '.ps1', '.gradle', '.maven', '.pom'
}

# File extensions that should never contain binary content
TEXT_ONLY_EXTENSIONS = {
    '.txt', '.md', '.rst', '.json', '.xml', '.yml', '.yaml',
    '.properties', '.cfg', '.conf', '.ini', '.log', '.csv'
}


class FileTypeMismatchDetector(Detector):
    """Detects files with extensions that don't match their actual content type."""

    MESSAGE_TEMPLATE = "File '%s' has extension '%s' but appears to be a '%s' file"

    def __init__(self):
        super().__init__(
            name="file_type_mismatch",
            description="Detects files with misleading extensions that don't match their actual content type",
        )

    @staticmethod
    def detect_file_type_by_signature(file_path: str) -> Optional[str]:
        """
        Detect the actual file type based on file signature (magic bytes).

        Args:
            file_path (str): Path to the file to analyze

        Returns:
            Optional[str]: Detected file extension or None if not detected
        """
        try:
            with open(file_path, 'rb') as f:
                # Read first 32 bytes for signature detection
                header = f.read(32)

                # Special case for RIFF files (WebP, WAV, AVI)
                if header.startswith(b'RIFF') and len(header) >= 12:
                    if header[8:12] == b'WEBP':
                        return '.webp'
                    elif header[8:12] == b'WAVE':
                        return '.wav'
                    elif header[8:12] == b'AVI ':
                        return '.avi'
                # Check against known signatures
                for signature, file_type in FILE_SIGNATURES.items():
                    if header.startswith(signature):
                        return file_type

                return None

        except (IOError, OSError) as e:
            log.warning(f"Could not read file {file_path}: {e}")
            return None

    @staticmethod
    def is_likely_binary(file_path: str) -> bool:
        """
        Check if a file is likely binary based on content analysis.

        Args:
            file_path (str): Path to the file to analyze

        Returns:
            bool: True if file appears to be binary
        """
        try:
            with open(file_path, 'rb') as f:
                # Read first 1KB for analysis
                chunk = f.read(1024)

                if not chunk:
                    return False

                # Check for null bytes (strong indicator of binary)
                if b'\x00' in chunk:
                    return True

                # Check for high ratio of non-printable characters
                printable_chars = sum(1 for byte in chunk if 32 <= byte <= 126 or byte in [9, 10, 13])
                ratio = printable_chars / len(chunk)

                # If less than 80% printable characters, likely binary
                return ratio < 0.8

        except (IOError, OSError):
            return False

    @abstractmethod
    def get_package_files(self, package_info: dict, path: str) -> Dict[str, str]:
        """
        Get the files in the package to analyze.

        Args:
            package_info (dict): Package metadata
            path (str): Package path

        Returns:
            Dict[str, str]: Mapping of relative file paths to absolute file paths
        """
        pass

    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        """
        Detect file type mismatches in the package.

        Args:
            package_info: Package metadata
            path: Package path
            name: Package name
            version: Package version

        Returns:
            tuple[bool, str]: (True if mismatches found, description of issues)
        """
        log.debug("file type mismatch general detect()...")
        if path is None:
            return False, "No package path provided"

        try:
            # package files from the decompressed project: {rel_path: abs_path}
            package_files: dict[str, str] = self.get_package_files(package_info, path)
        except Exception as e:
            log.warning(f"Could not get package files: {e}")
            return False, "Could not analyze package files"

        mismatches = []

        for relative_path, absolute_path in package_files.items():
            if not os.path.isfile(absolute_path):
                continue

            # Get file extension
            file_extension = os.path.splitext(relative_path)[1].lower()
            # Skip files without extensions
            if not file_extension:
                continue

            # Detect actual file type by signature
            detected_type: str | None = self.detect_file_type_by_signature(absolute_path)

            # Check for signature-based mismatch
            if detected_type and detected_type != file_extension:
                # Allow some common exceptions (e.g., .jar is ZIP-based)
                if not self._is_acceptable_mismatch(file_extension, detected_type):
                    mismatches.append({
                        'file': relative_path,
                        'claimed_extension': file_extension,
                        'detected_type': detected_type,
                        'reason': 'signature_mismatch'
                    })

            # Check for binary content in text-only files
            elif file_extension in TEXT_ONLY_EXTENSIONS:
                if self.is_likely_binary(absolute_path):
                    mismatches.append({
                        'file': relative_path,
                        'claimed_extension': file_extension,
                        'detected_type': 'binary',
                        'reason': 'binary_in_text_extension'
                    })

        if mismatches:
            messages = []
            for mismatch in mismatches:
                if mismatch['reason'] == 'signature_mismatch':
                    messages.append(
                        self.MESSAGE_TEMPLATE % (
                            mismatch['file'],
                            mismatch['claimed_extension'],
                            mismatch['detected_type']
                        )
                    )
                else:
                    messages.append(
                        f"File '{mismatch['file']}' has text extension '{mismatch['claimed_extension']}' "
                        "but contains binary data"
                    )

            return True, "\n".join(messages)

        return False, "No file type mismatches detected"

    @staticmethod
    def _is_acceptable_mismatch(claimed_ext: str, detected_type: str) -> bool:
        """
        Check if a file type mismatch is acceptable (e.g., JAR files are ZIP-based).

        Args:
            claimed_ext (str): Claimed file extension
            detected_type (str): Detected file type

        Returns:
            bool: True if the mismatch is acceptable
        """
        acceptable_mismatches = {
            # JAR, WAR, EAR are ZIP-based
            ('.jar', '.zip'),
            ('.war', '.zip'),
            ('.ear', '.zip'),
            # Android APK is ZIP-based
            ('.apk', '.zip'),
            # Office documents are ZIP-based (newer formats)
            ('.docx', '.zip'),
            ('.xlsx', '.zip'),
            ('.pptx', '.zip'),
            # Some other ZIP-based formats
            ('.odt', '.zip'),
            ('.ods', '.zip'),
            ('.odp', '.zip'),
            ('.macho', '.class')
        }

        return (claimed_ext, detected_type) in acceptable_mismatches
