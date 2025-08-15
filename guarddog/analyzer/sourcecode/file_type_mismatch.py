from abc import abstractmethod
from typing import Dict
import os
import logging
import magic
import mimetypes

from guarddog.analyzer.sourcecode.detector import Detector

log = logging.getLogger("guarddog")

# Common file signatures (magic bytes) for detection
FILE_SIGNATURES = {
    # Executables
    b"\x4d\x5a": ".exe",  # PE/DOS executable
    b"\x7fELF": ".elf",  # ELF executable (Linux)
    b"\xfe\xed\xfa\xce": ".macho",  # Mach-O (macOS)
    b"\xfe\xed\xfa\xcf": ".macho",  # Mach-O 64-bit
    b"\xca\xfe\xba\xbe": ".class",  # Mach-O universal binary
    # Archives
    b"PK\x03\x04": ".zip",  # ZIP archive (also JAR, WAR, etc.)
    b"PK\x05\x06": ".zip",  # Empty ZIP
    b"PK\x07\x08": ".zip",  # Spanned ZIP
    b"\x1f\x8b\x08": ".gz",  # GZIP
    b"BZh": ".bz2",  # BZIP2
    b"\x37\x7a\xbc\xaf\x27\x1c": ".7z",  # 7-Zip
    b"Rar!\x1a\x07\x00": ".rar",  # RAR archive
    b"Rar!\x1a\x07\x01\x00": ".rar",  # RAR 5.0+
    # Images
    b"\xff\xd8\xff": ".jpg",  # JPEG
    b"\x89PNG\r\n\x1a\n": ".png",  # PNG
    b"GIF87a": ".gif",  # GIF87a
    b"GIF89a": ".gif",  # GIF89a
    b"BM": ".bmp",  # Bitmap
    b"RIFF": ".webp",  # WebP (when followed by WEBP)
    # Documents
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": ".doc",  # MS Office (legacy)
    b"%PDF": ".pdf",  # PDF
    # Scripts and binaries that might be disguised
    b"#!/bin/sh": ".sh",  # Shell script
    b"#!/bin/bash": ".sh",  # Bash script
    b"#!/usr/bin/env python": ".py",  # Python script
    b"#!/usr/bin/env node": ".js",  # Node.js script
    # Other suspicious files
    b"\x00\x00\x01\x00": ".ico",  # Windows icon
    b"\x00\x00\x02\x00": ".cur",  # Windows cursor
}

# File extensions that are commonly safe text/config files
SAFE_TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".rst",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".properties",
    ".cfg",
    ".conf",
    ".ini",
    ".log",
    ".csv",
    ".java",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".css",
    ".sql",
    ".sh",
    ".bat",
    ".ps1",
    ".gradle",
    ".maven",
    ".pom",
}

# File extensions that should never contain binary content
TEXT_ONLY_EXTENSIONS = {
    ".txt",
    ".md",
    ".rst",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".properties",
    ".cfg",
    ".conf",
    ".ini",
    ".log",
    ".csv",
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
    def detect_file_type_by_signature(file_path: str) -> str | None:
        """
        Detect the actual file type based on file signature (magic bytes).

        Args:
            file_path (str): Path to the file to analyze

        Returns:
            Optional[str]: Detected file extension or None if not detected
        """
        try:
            # get MIME type from file's content
            mime_type = magic.from_file(file_path, mime=True)

            # get extension from MIME type
            extension = mimetypes.guess_extension(mime_type)
            log.debug(f"Mime type: {mime_type} extension: {extension}\n")
            return extension

        except FileNotFoundError:
            log.error(f"Error: File not found at '{file_path}'")
            return None
        except Exception as e:
            log.error(f"An error occurred: {e}")
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
            with open(file_path, "rb") as f:
                # Read first 1KB for analysis
                chunk = f.read(1024)

                if not chunk:
                    return False

                # Check for null bytes (strong indicator of binary)
                if b"\x00" in chunk:
                    return True

                # Check for high ratio of non-printable characters
                printable_chars = sum(
                    1 for byte in chunk if 32 <= byte <= 126 or byte in [9, 10, 13]
                )
                ratio = printable_chars / len(chunk)

                # If less than 80% printable characters, likely binary
                return ratio < 0.8

        except (IOError, OSError):
            return False

    @abstractmethod
    def get_package_files(self, path: str) -> Dict[str, str]:
        """
        Get the files in the package to analyze.

        Args:
            path (str): Package path

        Returns:
            Dict[str, str]: Mapping of relative file paths to absolute file paths
        """
        pass

    def detect(self, path: str | None = None) -> tuple[bool, str | None]:
        """
        Detect file type mismatches in the package.

        Args:
            path: Package path
            name: Package name
            version: Package version

        Returns:
            tuple[bool, str]: (True if mismatches found, description of issues)
        """
        if path is None:
            return False, "No package path provided"

        # package files from the decompressed project: {rel_path: abs_path}
        package_files: dict[str, str] = self.get_package_files(path)

        if not package_files:
            log.error(f"Could not find files in {path}.")
            return False, "Could not find files in the package"

        mismatches = []
        for relative_path, absolute_path in package_files.items():
            if not os.path.isfile(absolute_path):
                continue

            # Get file extension
            file_extension = os.path.splitext(relative_path)[1].lower()
            log.debug(relative_path)
            log.debug(file_extension)

            # Detect actual file type by signature
            detected_type: str | None = self.detect_file_type_by_signature(
                absolute_path
            )
            # Check for signature-based mismatch
            if (detected_type and not file_extension) or (
                detected_type and file_extension and detected_type != file_extension
            ):
                # Allow some common exceptions (e.g., .jar is ZIP-based)
                log.debug(f"mismatch {detected_type} {file_extension}")
                if not self._is_acceptable_mismatch(file_extension, detected_type):
                    log.debug(
                        f"found mismatch! {detected_type} but .{file_extension}\n"
                    )
                    mismatches.append(
                        {
                            "file": relative_path,
                            "claimed_extension": file_extension,
                            "detected_type": detected_type,
                            "reason": "signature_mismatch",
                        }
                    )

            # Check for binary content in text-only files - no magic numbers
            elif file_extension in TEXT_ONLY_EXTENSIONS:
                if self.is_likely_binary(absolute_path):
                    mismatches.append(
                        {
                            "file": relative_path,
                            "claimed_extension": file_extension,
                            "detected_type": "binary",
                            "reason": "binary_in_text_extension",
                        }
                    )

        if mismatches:
            messages = []
            for mismatch in mismatches:
                if mismatch["reason"] == "signature_mismatch":
                    messages.append(
                        self.MESSAGE_TEMPLATE
                        % (
                            mismatch["file"],
                            mismatch["claimed_extension"],
                            mismatch["detected_type"],
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
            (".jar", ".zip"),
            (".war", ".zip"),
            (".ear", ".zip"),
            # Android APK is ZIP-based
            (".apk", ".zip"),
            # Office documents are ZIP-based (newer formats)
            (".docx", ".zip"),
            (".xlsx", ".zip"),
            (".pptx", ".zip"),
            # Some other ZIP-based formats
            (".odt", ".zip"),
            (".ods", ".zip"),
            (".odp", ".zip"),
            (".macho", ".class"),
        }

        return (claimed_ext, detected_type) in acceptable_mismatches
