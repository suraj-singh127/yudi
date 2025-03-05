import re
from bs4 import BeautifulSoup

# Regex patterns for extracting IOCs
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
URL_REGEX = re.compile(r'\bhttps?://[^\s<>"]+\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
MITRE_REGEX = re.compile(r'\bT\d{4}\b')  # MITRE ATT&CK Techniques (e.g., T1059)

def extract_iocs(text):
    """Extract IOCs (IPs, URLs, domains, hashes, MITRE techniques) from text."""
    iocs = {
        "ips": list(set(IP_REGEX.findall(text))),
        "domains": list(set(DOMAIN_REGEX.findall(text))),
        "urls": list(set(URL_REGEX.findall(text))),
        "hashes": {
            "md5": list(set(MD5_REGEX.findall(text))),
            "sha1": list(set(SHA1_REGEX.findall(text))),
            "sha256": list(set(SHA256_REGEX.findall(text)))
        },
        "mitre_techniques": list(set(MITRE_REGEX.findall(text)))
    }
    return iocs

def extract_content(html):
    """Extract meaningful text and IOCs from HTML."""
    soup = BeautifulSoup(html, "html.parser")

    # Extract page title
    title = soup.title.string if soup.title else "No Title"

    # Extract visible text
    text = ' '.join(soup.stripped_strings)

    # Extract IOCs from the text
    iocs = extract_iocs(text)

    return {"title": title, "text_snippet": text[:1000], "iocs": iocs}

# Example usage (test run)
if __name__ == "__main__":
    sample_html = "<html><head><title>Threat Report</title></head><body>Detected T1059, IP: 192.168.1.1, URL: http://malicious.com</body></html>"
    result = extract_content(sample_html)
    print(result)
