from typing import Optional
import os

from guarddog.analyzer.sourcecode.bundled_binary import BundledBinary
from guarddog.utils.archives import DECOMPRESSED_PATH


class MavenBundledBinary(BundledBinary):
    def detect(self, path: Optional[str] = None) -> tuple[bool, str]:
        """
        Get the path of the decompressed java archive to analyse all the resulting files for bundled binary
        Or if no decompressed path, analyses the project at path
        """
        if not path:
            raise ValueError("path is needed to run heuristic " + self.get_name())

        decompressed_path = os.path.join(path, DECOMPRESSED_PATH)
        if decompressed_path and os.path.exists(decompressed_path):
            base_path = decompressed_path
        else:
            base_path = path

        return super().detect(base_path)
