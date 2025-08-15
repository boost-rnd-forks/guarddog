import xml.etree.ElementTree as ET
import logging
import re

from guarddog.utils.archives import find_pom

NAMESPACE = {"mvn": "http://maven.apache.org/POM/4.0.0"}
log = logging.getLogger("guarddog")


def get_email_addresses(path: str) -> set[str]:
    """
    Extract email addresses from Maven package metadata.
    Args:
        package_info (dict): Maven package metadata
    Returns:
        set[str]: Set of email addresses found in the metadata
    """
    log.debug("looking for pom to find developer's emails...")
    pom_path = find_pom(path)
    if not pom_path:
        log.error(f"Could not find pom.xml in {path}")
        return set()
    emails: list[str] = []
    # find email
    tree = ET.parse(pom_path)
    root = tree.getroot()
    emails = []
    for dev in root.findall(".//mvn:developer", NAMESPACE):
        email = dev.find("mvn:email", NAMESPACE)
        if email is not None and email.text:
            normalized_email: str = normalize_email(email.text.strip())
            emails.append(normalized_email)
    if not emails:
        log.warning("No email found in the pom.")
    return set(emails)


def normalize_email(email: str) -> str:
    """
    Normalize emails "name ([at]) domain.com"
    into emails "name@domain.com"
    """
    if "@" not in email:
        normalized_email = re.sub(
            r"\s*(\(|\[)?\s*at\s*(\)|\])?\s*", "@", email, flags=re.IGNORECASE
        )
    else:
        normalized_email = email
    return normalized_email.strip()
