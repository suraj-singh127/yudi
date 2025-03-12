import ipaddress
import re

# classifying user input using into three categories using regex
def classify_input(user_input,flag):
    # Check for IP address (IPv4 & IPv6)
    try:
        ipaddress.ip_address(user_input)
        return "IP"==flag , user_input
    except ValueError:
        pass
    
    # Check for URL
    url_pattern = re.compile(
        r"^(https?://)?"  # Optional http or https
        r"(([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"  # Domain name
        r"|localhost"  # OR localhost
        r"|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # OR IPv4
        r"|(\[[a-fA-F0-9:]+\]))"  # OR IPv6
        r"(:\d+)?(/.*)?$"  # Optional port & path
    )

    match = url_pattern.match(user_input)

    if match:
        return "URL"==flag,match.group(2)

    # Define hash regex patterns
    hash_patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA-1": r"^[a-fA-F0-9]{40}$",
        "SHA-256": r"^[a-fA-F0-9]{64}$",
        "SHA-512": r"^[a-fA-F0-9]{128}$",
    }

    # Check if input matches any hash format
    for hash_type, pattern in hash_patterns.items():
        if re.fullmatch(pattern, user_input):
            return "HASH"==flag, user_input

    return None