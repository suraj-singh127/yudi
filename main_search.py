import asyncio
import json
import os
import dotenv
from datetime import datetime
from urlscan_query import urlscan_submission
from virustotal_query import check_virustotal
from abuse_ipdb_check import check_abuseipdb
from classification import classify_input
from virustotal_query import search_virus_total
import aiohttp
import aiofiles
import shodan
from shodan_check import fetch_shodan_data
import pdb

dotenv.load_dotenv()

# 🔹 Function to Print Stylish Banner
def print_banner():
    banner = """
    ██    ██ ██    ██ ██████     ██   
    ██    ██ ██    ██ ██    █    ██ 
    ██    ██ ██    ██ ██    █    ██   
       ██    ██    ██ ██    █    ██       
       ██      ████   ██████     ██  
    --------------------------------------
      🔍 Threat Intelligence Lookup 🔍
    """
    print(banner)

async def fetch_api_result(api_function, api_key, ioc):
    """
    Calls an API function asynchronously, handles errors, and ensures a valid response.
    """
    try:
        print(f"[INFO] Calling API: {api_function.__name__} for {ioc}...")
        response = await api_function(api_key=api_key, ioc=ioc)

        if not response:
            print(f"[ERROR] No response received from {api_function.__name__}.")
            return {"error": "No response received"}

        if isinstance(response, dict) and "error" in response:
            print(f"[ERROR] API error from {api_function.__name__}: {response['error']}")
            return {"error": f"API error: {response['error']}"}

        print(f"[SUCCESS] Response received from {api_function.__name__}!")
        return response

    except asyncio.TimeoutError:
        print(f"[ERROR] Request to {api_function.__name__} timed out!")
        return {"error": "Request timed out"}

    except Exception as e:
        print(f"[ERROR] Unexpected error in {api_function.__name__}: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}"}



async def make_api_calls(api_keys, ioc, classification):
    """
    Calls appropriate API checks based on the type of IOC (IP, HASH, URL).
    """
    api_requests = []
    

    print("\n[INFO] Collecting endpoints for API calls...")

    if classification == "IP":
        api_requests.append({"function": check_abuseipdb, "api_key": api_keys["abuseipdb"], "ioc": ioc})
        api_requests.append({"function": search_virus_total, "api_key": api_keys["virustotal"], "ioc": ioc})
        print("[INFO] Fetching results from AbuseIPDB and VirusTotal for IP...")

    elif classification == "HASH":
        api_requests.append({"function": search_virus_total, "api_key": api_keys["virustotal"], "ioc": ioc})
        print("[INFO] Fetching results from VirusTotal for HASH...")

    elif classification == "URL":
        api_requests.append({"function": search_virus_total, "api_key": api_keys["virustotal"], "ioc": ioc})
        api_requests.append({"function": urlscan_submission, "api_key": api_keys["urlscan"], "ioc": ioc})
        print("[INFO] Fetching results from VirusTotal, URLHaus, and URLScan.io for URL...")

    print(f"[SUCCESS] {len(api_requests)} API calls prepared.")
    return api_requests

async def save_json_to_file(data, filename):
    """
    Saves JSON data to a file asynchronously.
    """
    print(f"[INFO] Saving data to {filename}...")
    async with aiofiles.open(filename, "a") as file:
        await file.write(json.dumps(data, indent=4) + ",")
    print(f"[SUCCESS] File saved: {filename}")

async def main():
    print_banner()  # 🔹 Show the banner at the start

    api_keys = {
        "virustotal": os.getenv("VT_KEY"),
        "abuseipdb": os.getenv("IPDB_KEY"),
        "abusech": os.getenv("ABUSECH_KEY"),
        "urlscan": os.getenv("URLSCAN_KEY"),
        "shodan" : os.getenv("SHODAN_KEY")
    }

    print("\n🔹 Welcome to the Threat Intelligence Lookup Tool 🔍")
    
    ioc = input("\n[INPUT] Enter an IOC (Hash, URL, Domain, or IP): ")
    
    classification = classify_input(ioc)
    print(f"\n[INFO] Input classified as - {classification}")

    api_calls = await make_api_calls(api_keys, ioc, classification)


    if not api_calls:
        print("[ERROR] No valid API calls generated. Exiting...")
        return

    print("\n[INFO] Initiating API calls...")
    print(api_calls)
    tasks = [fetch_api_result(api["function"], api["api_key"], api["ioc"]) for api in api_calls]
    results = await asyncio.gather(*tasks)

    api_shodan = shodan.Shodan(api_keys["shodan"])
    shodan_result = await fetch_shodan_data(classification,api_shodan,ioc)
    results.append(shodan_result)
    
    filename = f"{ioc}_report.json"
    
    for result in results:
        await save_json_to_file(result, filename)

    print(f"\n[COMPLETE] All responses saved to {filename}.")
    print("\n🚀 Execution completed. Check the report for details.")

if __name__ == "__main__":
    asyncio.run(main())
