
# YUDI - Threat Intelligence Lookup Tool

**YUDI** is an open-source tool designed to help cybersecurity professionals and researchers investigate threat intelligence data from various sources and feeds. The tool focuses on querying Indicators of Compromise (IOCs), filtering data, and drawing relations between different types of IOCs.

YUDI provides an easy way to look up IOCs, including IP addresses, hashes, domains, URLs, and more. It integrates with various external threat intelligence platforms to gather valuable data on security threats.

## Features

- **IOC Lookup**: Query a variety of IOCs including IPs, URLs, domains, and hashes.
- **Integration with OTX**: Fetch threat intelligence from the Open Threat Exchange (OTX) and other feeds.
- **Asynchronous Calls**: Handle multiple IOC lookups concurrently for efficient threat intelligence investigations.
- **Comprehensive IOC Classification**: Automatically classify IOCs into different types (IP, hash, domain, URL).
- **Error Handling and Debugging**: Built-in error handling and debug logging for easier troubleshooting.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/yudi.git
   cd yudi


