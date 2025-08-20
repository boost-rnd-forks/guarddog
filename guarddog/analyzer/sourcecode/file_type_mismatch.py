from abc import abstractmethod
from typing import Dict
import os
import logging
import magic # type: ignore
import mimetypes

from guarddog.analyzer.sourcecode.detector import Detector

log = logging.getLogger("guarddog")

# File extensions that should never contain binary content
ACCEPTABLE_TEXT_EXTENSIONS: set = {
    ".txt",
    ".md",
    "html",
    ".gradle",
    ".java",
    ".rst",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".properties",
    ".pro",
    ".cfg",
    ".conf",
    ".ini",
    ".log",
    ".csv",
    ".mf",
    "",
}

ACCEPTABLE_ZIP_EXTENSIONS: set = {
    ".zip",
    # Java Archives
    ".jar",  # Java Archive
    ".war",  # Web Application Archive
    ".ear",  # Enterprise Archive
    # Android and iOS Packages
    ".apk",  # Android Package
    ".ipa",  # iOS App Store Package
    # Microsoft Office Open XML (OOXML)
    ".docx",  # Word Document
    ".xlsx",  # Excel Spreadsheet
    ".pptx",  # PowerPoint Presentation
    ".docm",  # Word Macro-Enabled Document
    ".xlsm",  # Excel Macro-Enabled Spreadsheet
    ".pptm",  # PowerPoint Macro-Enabled Presentation
    ".vsdx",  # Visio Drawing
    ".xps",  # XML Paper Specification
    # OpenDocument Format (ODF)
    ".odt",  # OpenDocument Text
    ".ods",  # OpenDocument Spreadsheet
    ".odp",  # OpenDocument Presentation
    ".odg",  # OpenDocument Graphics
    # Other common formats
    ".epub",  # Electronic Publication (e-book)
    ".xpi",  # Firefox/Thunderbird Extension
}

ACCEPTABLE_CLASS_EXTENSIONS: set = {".class", ".java-applet"}


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
            # get mime type from file
            mime_type = magic.from_file(file_path, mime=True)

            # get extension from mime type
            extension = mimetypes.guess_extension(mime_type)
            if not extension:
                extension = "." + mime_type.split("/")[-1].split(".")[-1].replace(
                    "x-", ""
                )
                if extension == ".empty":
                    extension = ""
            return extension

        except FileNotFoundError:
            log.error(f"Error: File not found at '{file_path}'")
            return None
        except Exception as e:
            log.error(f"An error occurred: {e}")
            return None

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

            # Detect actual file type by signature
            detected_type: str | None = self.detect_file_type_by_signature(
                absolute_path
            )

            # Check for signature-based mismatch
            if (detected_type and not file_extension) or (
                detected_type
                and file_extension
                and not detected_type.startswith(file_extension)
            ):
                # Allow some common exceptions (e.g., .jar is ZIP-based)
                if not self._is_acceptable_mismatch(file_extension, detected_type):
                    log.debug(
                        f"found mismatch! {relative_path}: {detected_type} detected but extension {file_extension}\n"
                    )
                    mismatches.append(
                        {
                            "file": relative_path,
                            "claimed_extension": file_extension,
                            "detected_type": detected_type,
                        }
                    )

        if mismatches:
            messages = []
            for mismatch in mismatches:
                messages.append(
                    self.MESSAGE_TEMPLATE
                    % (
                        mismatch["file"],
                        mismatch["claimed_extension"],
                        mismatch["detected_type"],
                    )
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
        acceptable_zip_mismatches = set(
            (ext, ".zip") for ext in ACCEPTABLE_ZIP_EXTENSIONS
        )
        acceptable_txt_mismatches = set(
            (ext, ".txt") for ext in ACCEPTABLE_TEXT_EXTENSIONS
        )
        acceptable_class_mismatches = set(
            (ext, ".class") for ext in ACCEPTABLE_CLASS_EXTENSIONS
        )
        acceptable_mismatches = acceptable_txt_mismatches.union(
            acceptable_zip_mismatches
        ).union(acceptable_class_mismatches)
        return (claimed_ext, detected_type) in acceptable_mismatches or (
            detected_type,
            claimed_ext,
        ) in acceptable_mismatches
