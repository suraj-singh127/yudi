from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from concurrent.futures import ThreadPoolExecutor
import os
from typing import List
import time
import re
import json
from typing import Dict, List

ES_INDEX = "iocs"

# Initialize WebDriver options
def get_webdriver():
    print("Initializing WebDriver...")
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    # Use ChromeDriverManager to install and manage ChromeDriver automatically
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    print("WebDriver initialized.")
    return driver

def fetch_url(url):
    try:
        print(f"Fetching URL: {url}")
        driver = get_webdriver()
        driver.get(url)
        time.sleep(2)  # Wait for page to load
        page_source = driver.page_source
        driver.quit()
        print(f"Successfully fetched {url}")
        return page_source
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def scrape_iocs_from_urls(urls: List[str], es):
    """Scrapes IOCs from a list of URLs using multiple WebDriver instances."""
    print("Starting IOC scraping from URLs...")
    url_ioc_map = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        print(f"Submitting {len(urls)} URLs to fetch concurrently...")
        results = {url: executor.submit(fetch_url, url) for url in urls}

    for url, future in results.items():
        print(f"Processing result for {url}...")
        response = future.result()
        if response:
            print(f"Extracting IOCs from {url}...")
            iocs = extract_iocs(response)
            url_ioc_map[url] = iocs
            index_to_elasticsearch(url, iocs, es)
            print(f"Extracted IOCs from {url}")
        else:
            print(f"No data returned for {url}")
            
    print("IOC scraping complete.")

    return url_ioc_map

def extract_iocs(page_source: str) -> Dict[str, List]:
    """Extracts IOCs from the entire page source at once."""
    print("Extracting IOCs using regex patterns...")
    IOC_PATTERNS = {
        "urls": re.compile(r"https?:\/\/[^\s\"\'<>]+"),
        "domains": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "ipv6": re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b"),
        "hashes": {
            "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
            "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
            "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
            "SHA384": re.compile(r"\b[a-fA-F0-9]{96}\b"),
            "SHA512": re.compile(r"\b[a-fA-F0-9]{128}\b"),
            "SSDEEP": re.compile(r"\b\d{1,4}:[a-zA-Z0-9/+]{32,64}:[a-zA-Z0-9/+]{32,64}\b")  # Fuzzy hash
        }
    }

    extracted_iocs = {
        "urls": list(set(IOC_PATTERNS["urls"].findall(page_source))),
        "domains": list(set(IOC_PATTERNS["domains"].findall(page_source))),
        "ips": [],
        "hashes": []
    }

    # Extract IPs and remove false positives (filtering private/local IPs)
    extracted_ips = set(IOC_PATTERNS["ipv4"].findall(page_source)) | set(IOC_PATTERNS["ipv6"].findall(page_source))
    extracted_iocs["ips"] = [{"value": ip, "type": "IPv4" if "." in ip else "IPv6"} for ip in extracted_ips
                             if not is_private_ip(ip)]

    # Extract hashes and classify them
    for hash_type, pattern in IOC_PATTERNS["hashes"].items():
        for match in pattern.findall(page_source):
            extracted_iocs["hashes"].append({"value": match, "type": hash_type})

    print(f"Extracted {len(extracted_iocs['urls'])} URLs, {len(extracted_iocs['domains'])} domains, "
          f"{len(extracted_iocs['ips'])} IPs, {len(extracted_iocs['hashes'])} hashes.")
    return extracted_iocs

def is_private_ip(ip: str) -> bool:
    """Checks if an IP is private (e.g., local or reserved ranges)."""
    private_ranges = [
        re.compile(r"^10\..*"),          # 10.0.0.0/8
        re.compile(r"^192\.168\..*"),    # 192.168.0.0/16
        re.compile(r"^172\.(1[6-9]|2\d|3[01])\..*"),  # 172.16.0.0/12
        re.compile(r"^127\..*"),         # 127.0.0.0/8 (loopback)
        re.compile(r"^169\.254\..*"),    # 169.254.0.0/16 (APIPA)
        re.compile(r"^::1$"),            # IPv6 loopback
        re.compile(r"^fc..*|^fd..*")     # IPv6 unique local addresses
    ]
    
    return any(pattern.match(ip) for pattern in private_ranges)

def dump_iocs_to_json(url_ioc_map: Dict[str, Dict[str, List]], filename: str = "classified_iocs.json"):
    """Dumps the classified IOCs into a JSON file in the desired format."""
    try:
        print(f"Dumping IOCs to JSON file: {filename}...")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(url_ioc_map, f, indent=4)
        print(f"Classified IOCs saved to {filename}")
    except Exception as e:
        print(f"Error saving IOCs to JSON: {e}")

# Function to read URLs from the given text file
def read_urls_from_file(filename: str):
    print(filename)
    #if not os.path.exists(filename):
    #   print("File not found.")
    #    return []
    
    with open(filename, "r") as file:
        print("Opened file")
        urls = [line.strip() for line in file.readlines() if line.strip()]
    print(f"Read {len(urls)} URLs from file.")
    return urls

# Main function to handle the scraping and processing of IOCs
# Function accepts the scraping urls and then store it in elastic search index
def scrape_job(urls, es):

    if urls:
        print("Scraping IOCs from URLs...")
        classified_iocs = scrape_iocs_from_urls(urls,es)
        #dump_iocs_to_json(classified_iocs, "scraped.json")
        print("Scraping done... IOC's dumped to scraped.json as well as indexed in Elastic Search file")
        return classified_iocs
    else:
        print("No URLs found to scrape.")
        return {"error": "no results returned, some error encountered."}
    
def scrape_single_source(url,es):
    if url:
        print("Scraping IOC from URL.....")
        classified_ioc = extract_iocs(fetch_url(url))
        print(classified_ioc)
        return classified_ioc
    else:
        print("No URLs found to scrape.")
        return {"error": "no results returned, some error encountered."}
        

# indexing the scraped IOCs to elasticsearch
def index_to_elasticsearch(url, ioc_data,es):
    """Indexes IOCs in real time to Elasticsearch."""
    if not es.ping():
        print("Elasticsearch connection failed!")
        return
    
    doc = {
        "url": url,
        "iocs": ioc_data,
        "timestamp": "now"
    }
    
    # Index document using URL as ID (to prevent duplicates)
    response = es.index(index=ES_INDEX, id=url, document=doc)
    print(f"Indexed IOCs from {url} → {response['result']}")
