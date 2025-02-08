import asyncio
import requests
import time

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
        submitted_url = result.get("task", {}).get("url", "No URL found")
        report_url = result.get("task", {}).get("reportURL", "No report URL found")
        screenshot_url = result.get("task", {}).get("screenshotURL", "No screenshot available")
        verdicts = result.get("verdicts", {}).get("overall", {})

        return {
            "submitted_url": submitted_url,
            "report_url": report_url,
            "screenshot_url": screenshot_url,
            "verdicts": verdicts
        }

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
    print(scan_results)
