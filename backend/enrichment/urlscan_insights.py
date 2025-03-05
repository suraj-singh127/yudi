def extract_insights(scan_data):
    """
    Extracts useful security insights from URLScan.io JSON response.
    """
    insights = {}

    if not scan_data or "results" not in scan_data or not scan_data["results"]:
        print("[ERROR] No results found in URLScan data.")
        return None

    # Taking the first result (latest scan)
    scan = scan_data["results"][0]

    insights["URL"] = scan.get("task", {}).get("url", "N/A")
    insights["Scan Report"] = scan.get("task", {}).get("reportURL", "N/A")
    insights["Domain"] = scan.get("page", {}).get("domain", "N/A")
    insights["IP Address"] = scan.get("page", {}).get("ip", "N/A")
    insights["Reverse DNS"] = scan.get("page", {}).get("ptr", "N/A")
    
    # Security Verdicts
    insights["Malicious Verdict"] = scan.get("verdicts", {}).get("overall", {}).get("malicious", False)
    insights["Risk Score"] = scan.get("verdicts", {}).get("overall", {}).get("score", "N/A")
    
    # Redirection Information
    insights["Redirects"] = scan.get("data", {}).get("redirects", [])
    
    # SSL Certificate Info
    insights["SSL Certificate"] = scan.get("data", {}).get("certificates", "N/A")
    
    # HTTP Response Status
    insights["HTTP Status"] = scan.get("data", {}).get("httpStatus", "N/A")
    
    # Tracking Scripts & Requests
    insights["External Requests"] = scan.get("data", {}).get("requests", [])
    insights["Tracking Scripts"] = scan.get("data", {}).get("scripts", [])
    
    # Screenshot of the website
    insights["Screenshot URL"] = scan.get("task", {}).get("screenshotURL", "N/A")

    return insights