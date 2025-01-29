import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY_VT = os.getenv("VT_KEY")
API_KEY_IPDB = os.getenv("IPDB_KEY")



def fetch_virustotal(api_key, ioc):
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

def fetch_abuseipdb(api_key, ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Key": api_key, "Accept": "application/json"}
    response = requests.get(url, headers=headers, params=params)
    return response.json() if response.status_code == 200 else None

def fetch_urlhaus(url):
    query_url = "https://urlhaus-api.abuse.ch/v1/url/"
    response = requests.post(query_url, data={"url": url})
    return response.json() if response.status_code == 200 else None

def main():
    api_keys = {
        "virustotal": API_KEY_VT,
        "abuseipdb": API_KEY_IPDB,
    }
    
    ioc = input("Enter an IOC (Hash, URL, Domain, or IP): ")
    
    results = {}
    
    if "." in ioc or ":" in ioc:
        print("Fetching domain/IP-related data...")
        results["VirusTotal"] = fetch_virustotal(api_keys["virustotal"], ioc)
        results["AbuseIPDB"] = fetch_abuseipdb(api_keys["abuseipdb"], ioc) if ":" in ioc else None
    elif len(ioc) in [32, 40, 64]:  # Hash lengths for MD5, SHA1, SHA256
        print("Fetching hash-related data...")
        results["VirusTotal"] = fetch_virustotal(api_keys["virustotal"], ioc)
    
    print(json.dumps(results, indent=4))
    
    save_report_to_file(generate_html_report(results))

   
def generate_html_report(vt_data):
    if not vt_data:
        return "No data available for the report."
    
    data = vt_data
    
    # Start HTML content
    html_report = """
<html>
<head>
    <title>VirusTotal Domain Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }
        h1 { color: #005f7f; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        pre { background-color: #f9f9f9; padding: 10px; }
        .container { max-width: 800px; margin: 20px auto; }
        .summary { margin-top: 20px; }
        .warning { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>VirusTotal Domain Analysis Report</h1>
        
        <!-- Basic Domain Information Section -->
        <h2>Domain Information</h2>
        <table>
            <tr><th>Domain Name</th><td>{}</td></tr>
            <tr><th>Top-Level Domain (TLD)</th><td>{}</td></tr>
            <tr><th>Creation Date</th><td>{}</td></tr>
            <tr><th>Expiry Date</th><td>{}</td></tr>
            <tr><th>WHOIS Information</th><td><pre>{}</pre></td></tr>
        </table>

        <!-- Certificate Information Section -->
        <h2>Certificate Information</h2>
        <table>
            <tr><th>Certificate Issuer</th><td>{}</td></tr>
            <tr><th>Certificate Validity</th><td>{}</td></tr>
            <tr><th>Subject Alternative Names</th><td><pre>{}</pre></td></tr>
        </table>
        
        <!-- Analysis Results Section -->
        <h2>Analysis Results</h2>
        <table>
            <tr><th>Malicious</th><td>{}</td></tr>
            <tr><th>Suspicious</th><td>{}</td></tr>
            <tr><th>Undetected</th><td>{}</td></tr>
            <tr><th>Harmless</th><td>{}</td></tr>
            <tr><th>Timeouts</th><td>{}</td></tr>
        </table>
        
        <!-- Additional Information Section -->
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Reputation Score:</strong> {}</p>
            <p><strong>Last Analysis Date:</strong> {}</p>
            <p class="warning"><strong>Note:</strong> A high number of malicious detections may indicate the domain is suspicious. Please proceed with caution.</p>
        </div>
    </div>
</body>
</html>
""".format(
    data["data"]["domain_name"],
    data["tld"],
    data["creation_date"],
    data["expiry_date"],
    data["whois_info"],
    data["certificate_issuer"],
    data["certificate_validity"],
    data["certificate_san"],
    data["last_analysis_stats"]["malicious"],
    data["last_analysis_stats"]["suspicious"],
    data["last_analysis_stats"]["undetected"],
    data["last_analysis_stats"]["harmless"],
    data["last_analysis_stats"]["timeout"],
    data["reputation_score"],
    data["last_analysis_date"]
)
    
    return html_report

def save_report_to_file(html_report, filename='vt_report.html'):
    with open(filename, 'w') as f:
        f.write(html_report)
    print(f'Report saved to {filename}')

if __name__ == "__main__":
    main()