# Maven-specific metadata security rules
from typing import Type
from guarddog.analyzer.metadata.detector import Detector
from .repository_integrity_mismatch import MavenIntegrityMismatchDetector

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes: list[Type[Detector]] = [
    MavenIntegrityMismatchDetector,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
