import asyncio
import requests
import time
import csv
import json

# Submitting a url for scanning

async def submit_url_to_urlscan(api_key, url_to_scan, visibility="public"):
    """
    Submits a URL to URLScan.io for scanning.

    Parameters:
        api_key (str): The API key for URLScan.io.
        url_to_scan (str): The URL to be scanned.
        visibility (str): Scan visibility ('public' or 'private').

    Returns:
        dict: Contains scan ID and submission details or error message.
    """
    url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    data = {
        "url": url_to_scan,
        "visibility": visibility
    }

    try:
        # Submit URL asynchronously
        response = await asyncio.to_thread(requests.post, url, headers=headers, json=data)
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Parse response JSON
        result = response.json()
        scan_id = result.get("uuid")

        return {"scan_id": scan_id, "message": "Submission successful"}

    except requests.exceptions.HTTPError as http_err:
        return {"error": f"HTTP error occurred: {http_err}"}
    
    except requests.exceptions.RequestException as req_err:
        return {"error": f"Request error occurred: {req_err}"}
    
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

async def fetch_urlscan_results(api_key, scan_id, wait_time=15):
    """
    Fetches scan results from URLScan.io after submission.

    Parameters:
        api_key (str): The API key for URLScan.io.
        scan_id (str): The scan ID received after URL submission.
        wait_time (int): Time to wait before fetching results (in seconds).

    Returns:
        dict: Contains scan results, submitted URL, report URL, and verdicts.
    """
    url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }

    # Wait before fetching results to ensure scan is complete
    print(f"Waiting {wait_time} seconds for scan to complete...")
    time.sleep(wait_time)  # Consider polling for a better approach

    try:
        # Fetch results asynchronously
        response = await asyncio.to_thread(requests.get, url, headers=headers)
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Parse JSON response
        result = response.json()
        
        # Extract relevant details
        if result:
            print("[DEBUG] Report fetched successfully. Analyzing data...")
            intelligence = analyze_urlscan_data(result)

            # Check if any intelligence was gathered
            if intelligence:
                print("[DEBUG] Intelligence gathered successfully.")

            else:
                print("[INFO] No actionable intelligence found.")
        else:
            print("[ERROR] No report data available to analyze.")

        return result
    
    except requests.exceptions.HTTPError as http_err:
        return {"error": f"HTTP error occurred: {http_err}"}
    
    except requests.exceptions.RequestException as req_err:
        return {"error": f"Request error occurred: {req_err}"}
    
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

async def urlscan_submission(api_key,ioc):

    # Step 1: Submit URL for scanning
    submission_response = await submit_url_to_urlscan(api_key, ioc)
    if "scan_id" not in submission_response:
        print("Submission failed:", submission_response)
        return

    scan_id = submission_response["scan_id"]
    print(f"URL submitted successfully. Scan ID: {scan_id}")

    # Step 2: Fetch results after scan completion
    scan_results = await fetch_urlscan_results(api_key, scan_id)
    return scan_results

# Function to parse and analyze the URLScan report
def analyze_urlscan_data(report_data):
    print("[DEBUG] Analyzing URLScan data...")
    
    intelligence = {}

    # Extract the relevant fields
    url = report_data.get('url')
    hostname = report_data.get('domain', {}).get('hostname', '')
    ip = report_data.get('network', {}).get('ip', '')
    asn = report_data.get('network', {}).get('asn', '')
    technologies = report_data.get('technologies', [])
    http_headers = report_data.get('http', {})
    resources = report_data.get('resources', [])
    detections = report_data.get('detection', {})

    # 1. Check for suspicious domains or IPs
    if 'malicious' in detections:
        intelligence['malicious_detection'] = True
        print(f"[DEBUG] Malicious detection found for URL: {url}")

    # 2. Extract technology stack that could indicate suspicious behavior
    for tech in technologies:
        if "obfuscation" in tech.lower():  # Example filter
            intelligence['suspicious_technology'] = tech
            print(f"[DEBUG] Suspicious technology found: {tech}")

    # 3. Check resources for suspicious URLs
    for resource in resources:
        if 'malicious.com' in resource.get('url', ''):  # Example filter
            intelligence['suspicious_resource'] = resource['url']
            print(f"[DEBUG] Suspicious resource found: {resource['url']}")

    # 4. Check the ASN for known bad actor ASN
    if asn == "AS12345":  # Replace with a known malicious ASN
        intelligence['suspicious_asn'] = asn
        print(f"[DEBUG] Suspicious ASN detected: {asn}")

    return intelligence

# Function to generate and save intelligence as CSV
def save_intel_as_csv(intel_data, filename="intel_report.csv"):
    try:
        print(f"[DEBUG] Saving intelligence to CSV file: {filename}")
        keys = intel_data.keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(keys)  # Write headers
            writer.writerow(intel_data.values())  # Write data row
        print("[DEBUG] CSV report saved successfully.")
    except Exception as e:
        print(f"[ERROR] Error saving CSV report: {e}")

# Function to generate and save intelligence as JSON
def save_intel_as_json(intel_data, filename="intel_report.json"):
    try:
        print(f"[DEBUG] Saving intelligence to JSON file: {filename}")
        with open(filename, 'w') as json_file:
            json.dump(intel_data, json_file, indent=4)
        print("[DEBUG] JSON report saved successfully.")
    except Exception as e:
        print(f"[ERROR] Error saving JSON report: {e}")
