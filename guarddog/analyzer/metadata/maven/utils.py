def get_email_addresses(package_info: dict) -> set[str]:
    """
    Extract email addresses from Maven package metadata.
    
    Args:
        package_info (dict): Maven package metadata
        
    Returns:
        set[str]: Set of email addresses found in the metadata
    """
    emails = set()
    
    # Extract from developers
    developers = package_info.get("developers", [])
    for dev in developers:
        if "email" in dev:
            emails.add(dev["email"])
            
    # Extract from contributors
    contributors = package_info.get("contributors", [])
    for contrib in contributors:
        if "email" in contrib:
            emails.add(contrib["email"])
            
    return emails - {None, ""}
