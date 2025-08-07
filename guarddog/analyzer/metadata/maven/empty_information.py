"""Empty Information Detector

Detects if a package contains an empty description
"""

import logging
from typing import Optional

from guarddog.analyzer.metadata.empty_information import EmptyInfoDetector

log = logging.getLogger("guarddog")


class MavenEmptyInfoDetector(EmptyInfoDetector):
    def detect(
        self,
        package_info,
        path: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
    ) -> tuple[bool, str]:
        log.debug(
            f"Running Maven empty description heuristic on package {name} version {version}"
        )
        return (
            len(package_info.get("info").get("description").strip()) == 0,
            EmptyInfoDetector.MESSAGE_TEMPLATE % "Maven",
        )
