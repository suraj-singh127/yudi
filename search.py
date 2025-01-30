import requests
import json
import os
import re
import ipaddress

from dotenv import load_dotenv

load_dotenv()

API_KEY_VT = os.getenv("VT_KEY")
API_KEY_IPDB = os.getenv("IPDB_KEY")
API_KEY_ABUSECH = os.getenv("ABUSECH_KEY")



def fetch_virustotal(api_key, ioc):
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": api_key}
    return get_data(url=url,headers=headers,query_string="")

def fetch_abuseipdb(api_key, ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Key": api_key, "Accept": "application/json"}
    return get_data(url=url,headers=headers,query_string=params)

def fetch_urlhaus(url):
    query_url = "https://urlhaus-api.abuse.ch/v1/urls/recent"
    headers={
        "Auth-Key" : API_KEY_ABUSECH,
    }
    return post_data(query_url,headers=headers)

def get_data(url,headers,query_string):
    response = requests.request(method="GET",url=url,headers=headers,params=query_string)
    if response.status_code==200:
        print(f"Fetching from endpoint {url}.......Successful")
        return response.json()
    else:
        print(f"Fetching from resource failed.")
        return None

def post_data(url,params,headers):
    #making api call for fetching response
    response = requests.request(method="POST",url=url,params=params,headers=headers)
    if response.status_code==200:
        print(f"Fetching from endpoint {url}.......Successful")
        return response.json()
    else:
        print(f"Fetching from resource failed.")
        return None

import re
import ipaddress

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

# Function for making the api calls
def make_api_calls(api_keys,ioc,classification):
    results = {}

    if classification == "IP":
        results["AbuseIPDB"] = fetch_abuseipdb(api_key=api_keys["abuseipdb"],ip=ioc)
        results["VirusTotal"] = fetch_virustotal(api_key=api_keys["virustotal"],ioc=ioc)
        print(f"Json results from Abuse IPDB and Virus total cumulative........... \n")
    
    elif classification == "HASH":
        results["VirusTotal"] = fetch_virustotal(api_key=api_keys["virustotal"],ioc=ioc)
        print(f"JSON Results from Virus total")
    
    elif classification == "URL":
        results["VirusTotal"] = fetch_virustotal(api_key=api_keys["virustotal"],ioc=ioc)
        results["URL_Haus"] = fetch_virustotal(api_key=api_keys["abusech"],ioc=ioc)
        print(f"Json results from Abuse IPDB and Virus total cumulative........... \n")

def dump_report_json(vt_data):
    if not vt_data:
        return "No data available for the report."
    
    # dumping json data to check the data
    with open("response_vt.json","w") as file:
        json.dump(vt_data,file,indent=4)
    
    html_report = """"""
    
    return html_report

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

    # making api calls to respective sources
    make_api_calls(api_keys=api_keys,ioc=ioc,classification=classification)
    save_report_to_file(dump_report_json(results))

if __name__ == "__main__":
    main()