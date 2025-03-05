import argparse
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
import aiofiles
import shodan
from shodan_check import fetch_shodan_data
from get_key import extract_platform_keys

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

async def main():
    print_banner()  # 🔹 Show the banner at the start

    api_keys = {
        "virustotal": extract_platform_keys("virustotal")["api_key"],
        "abuseipdb": extract_platform_keys("abuseipdb")["api_key"],
        "abusech": os.getenv("ABUSECH_KEY"),
        "urlscan": extract_platform_keys("urlscan")["api_key"],
        "shodan" : extract_platform_keys("shodan")["api_key"]
    }

    print("\n🔹 Welcome to the Threat Intelligence Lookup Tool 🔍")

    # Argument Parsing
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Lookup Tool",
        epilog="This tool helps you query various threat intelligence APIs for IP, HASH, URL, or DOMAIN IOC data."
    )

    parser.add_argument(
        "ioc",
        type=str,
        help="The IOC (IP, HASH, URL, or Domain) you wish to look up."
    )
    parser.add_argument(
        "-t", "--type",
        choices=["IP", "HASH", "URL", "DOMAIN"],
        required=True,
        help="Specify the type of the IOC: 'IP', 'HASH', 'URL', or 'DOMAIN'."
    )

    args = parser.parse_args()

    # Use command-line arguments
    ioc = args.ioc
    classification = args.type
   
    ioc_check = classify_input(ioc,classification)

    if ioc_check:
        print("[SUCCESS] IOC entered matched successfully with type")
        print(f"IOC - {ioc_check[1]}")
        ioc = ioc_check[1]
    else:
        print("[ERROR] IOC Entered invalid ioc")

    api_calls = await make_api_calls(api_keys, ioc, classification)

    if not api_calls:
        print("[ERROR] No valid API calls generated. Exiting...")
        return

    print("\n[INFO] Initiating API calls...")

    # Create a dictionary of tasks where keys are function names (source identifiers)
    tasks = {
        api["function"].__name__: fetch_api_result(api["function"], api["api_key"], api["ioc"])
        for api in api_calls
    }

    # Gather responses while keeping track of the source
    responses = await asyncio.gather(*tasks.values())

    # Store results in a dictionary with source function names as keys
    results = {source: response for source, response in zip(tasks.keys(), responses)}

    # Fetch Shodan data separately and include it under its own key
    api_shodan = shodan.Shodan(api_keys["shodan"])
    shodan_result = await fetch_shodan_data(classification, api_shodan, ioc)
    results["shodan"] = shodan_result  # Add Shodan response separately

    # Save results in one single structured JSON file
    filename = "report.json"
    async with aiofiles.open(filename, "w") as file:  # 'w' ensures the file is overwritten, avoiding duplicates
        await file.write(json.dumps(results, indent=4))

    print(f"\n[COMPLETE] All responses saved to {filename}.")

    print("\n🚀 Execution completed. Check the report for details.")
    
if __name__=="__main__":
    asyncio.run(main())