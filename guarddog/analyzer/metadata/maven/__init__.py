
from guarddog.analyzer.metadata.detector import Detector
from guarddog.analyzer.metadata.maven.deceptive_author import MavenDeceptiveAuthor

MAVEN_METADATA_RULES: dict[str, Detector] = {}

classes = [
    MavenDeceptiveAuthor,
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
  