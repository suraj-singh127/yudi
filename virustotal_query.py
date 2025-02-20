import aiohttp


# Submitting a URL for analysis
async def check_virustotal(api_key, ioc):
    """
    Queries VirusTotal API to check a URL for threats.
    """
    api_endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key,
               'content-type': 'application/x-www-form-urlencoded'
               }
    data = {"url": ioc}

    print(f"[INFO] Sending request to VirusTotal to check URL: {ioc}")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(api_endpoint, headers=headers, data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"[INFO] Successfully retrieved data for URL: {ioc}")
                    return result
                else:
                    print(f"[ERROR] Failed to fetch data for {ioc}. Status Code: {response.status} ")
                    return None
    except Exception as e:
        print(f"[ERROR] Error querying VirusTotal for {ioc}: {str(e)}")
        return None

# Search VirusTotal by query (for hashes, domains, etc.)
async def search_virus_total(api_key, ioc):
    """
    Queries VirusTotal search API to search for IOCs like IPs, domains, or hashes.
    """
    api_endpoint = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    print(f"[INFO] Searching VirusTotal for IOC: {ioc}")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(api_endpoint, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"[INFO] Successfully fetched search results for IOC: {ioc}")
                    return result
                else:
                    print(f"[ERROR] Failed to search VirusTotal for {ioc}. Status Code: {response.status}")
                    return None
    except Exception as e:
        print(f"[ERROR] Error searching VirusTotal for {ioc}: {str(e)}")
        return None

