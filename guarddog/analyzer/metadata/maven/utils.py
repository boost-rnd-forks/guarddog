def get_email_addresses(package_info: dict) -> set[str]:
    """
    Extract email addresses from Maven package metadata.
    Args:
        package_info (dict): Maven package metadata
    Returns:
        set[str]: Set of email addresses found in the metadata
    """
    info = package_info.get("info", {})
    emails = info.get("email", [])
    if not isinstance(emails, (list, tuple, set)):
        return set()
    return set(emails)
