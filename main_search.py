import asyncio
import json
import os
import dotenv
from datetime import datetime
from urlhause_query import check_urlhaus
from urlscan_query import urlscan_submission
from virustotal_query import check_virustotal
from abuse_ipdb_check import check_abuseipdb
from classification import classify_input
from virustotal_query import search_virus_total

dotenv.load_dotenv()

async def fetch_api_result(api_function, api_key, ioc):
    """
    Calls an API function asynchronously, handles errors, and ensures a valid response.
    
    Parameters:
        api_function (function): The API query function to call.
        api_key (str): The API key to pass to the function.
        kwargs: Additional arguments for the API function.

    Returns:
        dict or str: API response JSON if successful, else error message.
    """
    try:
        response = await api_function(api_key=api_key, ioc = ioc)

        if not response:
            return {"error": "No response received"}

        if isinstance(response, dict) and "error" in response:
            return {"error": f"API error: {response['error']}"}

        return response

    except asyncio.TimeoutError:
        return {"error": "Request timed out"}
    
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

async def make_api_calls(api_keys, ioc, classification):
    print(api_keys)
    """
    Calls appropriate API checks based on the type of IOC (IP, HASH, URL).
    Saves responses to a JSON file and handles errors gracefully.
    
    Parameters:
        api_keys (dict): Dictionary containing API keys.
        ioc (str): The Indicator of Compromise (IP, URL, or HASH).
        classification (str): The type of IOC ("IP", "HASH", "URL").
    
    Returns:
        dict: JSON results from the relevant API queries.
    """
    api_requests = []

    print("Inside API requests function")

    if classification == "IP":
        api_requests.append(fetch_api_result(check_abuseipdb, api_keys["abuseipdb"],ioc))
        api_requests.append(fetch_api_result(check_virustotal, api_keys["virustotal"],ioc))
        print("Fetching results from AbuseIPDB and VirusTotal for IP...")

    elif classification == "HASH":
        api_requests.append(fetch_api_result(check_virustotal, api_keys["virustotal"],ioc))
        print("Fetching results from VirusTotal for HASH...")

    elif classification == "URL":
        api_requests.append(fetch_api_result(search_virus_total, api_keys["virustotal"],ioc))
        api_requests.append(fetch_api_result(check_urlhaus, api_keys["abusech"],ioc))
        api_requests.append(fetch_api_result(urlscan_submission, api_keys["urlscan"], ioc))
        
        print("Fetching results from VirusTotal, URLHaus, and URLScan.io for URL...")

    # Run all API calls asynchronously and collect results
    results = await asyncio.gather(*api_requests)

    # Save results to a JSON file
    save_results_to_file(results)

    return results

def save_results_to_file(data):
    """
    Saves the JSON results to a file with a timestamp.

    Parameters:
        data (dict): The JSON response from the security checks.
    """
    # Create results directory if not exists
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{results_dir}/security_results_{timestamp}.json"

    # Save the JSON data to file
    with open(filename,"+a") as f:
        json.dumps(data, indent=4)

    print(f"Results saved to {filename}")

# Example usage
async def main():
    api_keys = {
        "virustotal": os.getenv("VT_KEY"),
        "abuseipdb": os.getenv("IPDB_KEY"),
        "abusech": os.getenv("ABUSECH_KEY"),
        "urlscan": os.getenv("URLSCAN_KEY")
    }

    ioc = input("Enter an IOC (Hash, URL, Domain, or IP): ")
    
    classification = classify_input(ioc)
    print(f"Input matched as - {classification}")

    classification =  classify_input(ioc)

    result = await make_api_calls(api_keys, ioc, classification)
    save_results_to_file(result)

if __name__ == "__main__":
    asyncio.run(main())
