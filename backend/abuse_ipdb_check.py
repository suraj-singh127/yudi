import aiohttp

# Function takes in api key and ioc and returns the response

async def check_abuseipdb(api_key, ioc):
    """
    Queries AbuseIPDB to check if an IP address is reported for abuse.
    """
    api_endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}

    print(f"[INFO] Sending request to AbuseIPDB to check IP: {ioc}")
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(api_endpoint, headers=headers, params=params) as response:
                if response.status == 200:
                    result = await response.json()
                    print(f"[INFO] Successfully retrieved data for IP: {ioc}")
                    return result
                else:
                    print(f"[ERROR] Failed to fetch data for {ioc}. Status Code: {response.status}")
                    return None
    except Exception as e:
        print(f"[ERROR] Error querying AbuseIPDB for {ioc}: {str(e)}")
        return None
