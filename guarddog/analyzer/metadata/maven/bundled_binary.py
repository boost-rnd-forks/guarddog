from guarddog.analyzer.metadata.bundled_binary import BundledBinary
from typing import Optional


class MavenBundledBinary(BundledBinary):
    def detect(self, package_info, path: Optional[str] = None, name: Optional[str] = None,
               version: Optional[str] = None) -> tuple[bool, str]:
        """
            Get the path of the decompressed java archive to analyse all the resulting files for bundle binary
        """
        decompressed_path: str = package_info["path"]["decompressed_path"]
        return super().detect(package_info, decompressed_path, name, version)
