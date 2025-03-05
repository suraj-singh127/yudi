from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from typing import List
import time

# Initialize WebDriver options
def get_webdriver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    # Use ChromeDriverManager to install and manage ChromeDriver automatically
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    return driver

# Function to fetch content from URL
def fetch_url(url):
    try:
        driver = get_webdriver()
        driver.get(url)
        time.sleep(2)  # Wait for page to load
        page_source = driver.page_source
        driver.quit()
        return page_source
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

# Function to scrape IOCs from a list of URLs
def scrape_iocs_from_urls(urls: List[str]):
    iocs = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(fetch_url, urls))
    
    for response in results:
        if response:
            iocs.extend(extract_iocs(response))
    
    classified_iocs = classify_iocs(iocs)
    return classified_iocs

# Function to extract IOCs (Indicators of Compromise) from the page source
def extract_iocs(data: str):
    iocs = []
    for line in data.splitlines():
        line = line.strip()
        if line:
            iocs.append(line)
    return iocs

# Refined function to classify IOCs (Indicators of Compromise)
def classify_iocs(iocs: List[str]):
    classified = {"hashes": [], "domains": [], "urls": [], "ttps": []}
    
    # Regex patterns for more accurate classification
    url_pattern = re.compile(r"^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(:[0-9]+)?(/.*)?$")
    domain_pattern = re.compile(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}$")  # Basic domain regex
    hash_patterns = {
        "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
        "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
        "SHA256": re.compile(r"^[a-fA-F0-9]{64}$")
    }

    for ioc in iocs:
        ioc = ioc.strip()
        
        # Classify URL
        if url_pattern.match(ioc):
            classified["urls"].append(ioc)
        
        # Classify Domain
        elif domain_pattern.match(ioc):
            # Avoid IP addresses and add more refined domain matching
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ioc):
                classified["domains"].append(ioc)
        
        # Classify Hash (MD5, SHA1, SHA256)
        elif hash_patterns["MD5"].match(ioc):
            classified["hashes"].append(ioc)
        elif hash_patterns["SHA1"].match(ioc):
            classified["hashes"].append(ioc)
        elif hash_patterns["SHA256"].match(ioc):
            classified["hashes"].append(ioc)
        
        # If it's a potential TTP (any other unclassified IOC)
        else:
            classified["ttps"].append(ioc)
    
    return classified


# Function to read URLs from the given text file
def read_urls_from_file(filename: str):
    if not os.path.exists(filename):
        print("File not found.")
        return []
    
    with open(filename, "r") as file:
        urls = [line.strip() for line in file.readlines() if line.strip()]
    return urls

# Main function to handle the scraping and processing of IOCs
def main():
    filename = "open_source_threat_feeds.txt"
    urls = read_urls_from_file(filename)
    if urls:
        print("Scraping IOCs from URLs...")
        classified_iocs = scrape_iocs_from_urls(urls)
        print("Classified IOCs:", classified_iocs)
    else:
        print("No valid URLs found.")

if __name__ == "__main__":
    main()
