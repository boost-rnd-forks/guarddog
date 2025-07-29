# Maven-specific metadata security rules
# Currently empty - rules can be added here in the future
from typing import Type
from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.maven.bundled_binary import MavenBundledBinary

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenBundledBinary,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
