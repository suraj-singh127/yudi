import subprocess
import json

def fetch_dns_records(domain):
    """
    Fetches DMARC, SPF, DKIM, MX, and TXT records for a given domain using `dig`
    and returns the result as a dictionary.
    """
    record_types = ["TXT", "MX", "SPF", "CNAME"]
    results = {}

    for record in record_types:
        try:
            # Run dig command
            output = subprocess.run(["dig", "+short", record, domain], capture_output=True, text=True)
            
            # Store results if found
            if output.stdout.strip():
                results[record] = output.stdout.strip().split("\n")
            else:
                results[record] = []

        except Exception as e:
            results[record] = {"error": f"Error fetching {record}: {str(e)}"}

    # Fetch DMARC record explicitly (_dmarc.domain.com)
    try:
        dmarc_domain = f"_dmarc.{domain}"
        output = subprocess.run(["dig", "+short", "TXT", dmarc_domain], capture_output=True, text=True)
        results["DMARC"] = output.stdout.strip().split("\n") if output.stdout.strip() else []
    except Exception as e:
        results["DMARC"] = {"error": f"Error fetching DMARC: {str(e)}"}

    return json.dumps(results,indent=4)
