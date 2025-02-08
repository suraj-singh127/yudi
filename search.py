import requests
import json
import os
import re
import ipaddress
import asyncio
import tracemalloc
import aiohttp

tracemalloc.start()

from dotenv import load_dotenv

load_dotenv()

API_KEY_VT = os.getenv("VT_KEY")
API_KEY_IPDB = os.getenv("IPDB_KEY")
API_KEY_ABUSECH = os.getenv("ABUSECH_KEY")



def fetch_virustotal(api_key, ioc):
    
    print("Fetching Virus Total response.........")

    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": api_key}

    return { "url" : url, "method": "GET","headers" : headers }

def fetch_abuseipdb(api_key, ip):
    
    print("Fetching Abuse IPDB response")

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Key": api_key, "Accept": "application/json"}

    return { "url" : url, "method" : "GET", "headers": headers, "params" : params }

def fetch_urlhaus(api_key,ioc):
    
    print("Fetching URL Haus response from ")
    
    url = "https://urlhaus-api.abuse.ch/v1/url"
    headers={ "Auth-Key" : api_key}
    data = {"url": ioc }

    return { "url":url, "method":"POST" , "headers":headers, "params" : None, "data" : data}

async def fetch_data(url, session, method="GET", headers=None, params=None, data=None):
    """Fetch data from a URL using GET or POST, with headers and params support."""
    print(f"Making API call to the url {url} .........")
    try:
        if method.upper() == "GET":
            async with session.get(url, headers=headers, params=params) as response:
                response.raise_for_status()
                return await response.json()  # Parse JSON response

        elif method.upper() == "POST":
            async with session.post(url, headers=headers, json=data) as response:
                response.raise_for_status()
                return await response.json()  # Parse JSON response

        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    except aiohttp.ClientError as e:
        print(f"Error fetching {url}: {e}")
        return None

async def fetch_all_data(api_requests):
    """Fetch data from multiple sources concurrently."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            fetch_data(
                req["url"], session, req.get("method", "GET"),
                headers=req.get("headers"), params=req.get("params"), data=req.get("data")
            )
            for req in api_requests
        ]
        results = await asyncio.gather(*tasks)  # Run all tasks concurrently
        return results

# classifying user input using into three categories using regex
def classify_input(user_input):
    # Check for IP address (IPv4 & IPv6)
    try:
        ipaddress.ip_address(user_input)
        return "IP"
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
    if url_pattern.match(user_input):
        return "URL"

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
            return "HASH"

    return None

def check_urlhaus(url_to_check, auth_key):
    api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    
    headers = {
        "Auth-Key": auth_key
    }

    data = {
        "url": url_to_check
    }

    try:
        response = requests.post(api_endpoint, headers=headers, data=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

# Function for making the api calls
def make_api_calls(api_keys,ioc,classification):
    api_requests = []

    print("Inside API requests function")

    if classification == "IP":
        api_requests.append(fetch_abuseipdb(api_key=api_keys["abuseipdb"],ip=ioc))
        api_requests.append(fetch_virustotal(api_key=api_keys["virustotal"],ioc=ioc))
        print(f"Json results from Abuse IPDB and Virus total cumulative........... \n")
    
    elif classification == "HASH":
        api_requests.append(fetch_virustotal(api_key=api_keys["virustotal"],ioc=ioc))
        print(f"JSON Results from Virus total")
    
    elif classification == "URL":
        api_requests.append(fetch_virustotal(api_key=api_keys["virustotal"],ioc=ioc))
        api_requests.append(fetch_urlhaus(api_key=api_keys["abusech"],ioc=ioc))
        print(f"Json results from Abuse IPDB and Virus total cumulative........... \n")

    return api_requests

def dump_report_json(vt_data):
    if not vt_data:
        return "No data available for the report."
    
    # dumping json data to check the data
    with open("sample_reponse_ip.json","w") as file:
        json.dump(vt_data,file,indent=4)

def save_report_to_file(html_report, filename='vt_report.html'):
    with open(filename, 'w') as f:
        f.write(html_report)
    print(f'Report saved to {filename}')

    
def main():
    api_keys = {
        "virustotal": API_KEY_VT,
        "abuseipdb": API_KEY_IPDB,
        "abusech" : API_KEY_ABUSECH
    }
    
    ioc = input("Enter an IOC (Hash, URL, Domain, or IP): ")
    
    results = {}

    # Classifying user input to HASH, URL or IP
    classification = classify_input(ioc)
    print(f"Input matched as - {classification}")
    
    api_requests = make_api_calls(api_keys=api_keys,ioc=ioc,classification=classification)
    
    # Run async API requests
    results = asyncio.run(fetch_all_data(api_requests))

    print(json.dumps(results,indent=4))
    # Combine results into a single JSON response
    combined_data = {"results": [result for result in results if result]}

    # Print or process the combined data
    dump_report_json(combined_data)

if __name__ == "__main__":
    main()