# Maven-specific metadata security rules
# Currently empty - rules can be added here in the future

MAVEN_METADATA_RULES = {} 

classes = [
]

for detectorClass in classes:
    detectorInstance = detectorClass()  # type: ignore
    MAVEN_METADATA_RULES[detectorInstance.get_name()] = detectorInstance
