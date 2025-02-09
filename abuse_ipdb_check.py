import aiohttp
import pdb

# Function takes in api key and ioc and returns the response

pdb.set_trace()

async def check_abuseipdb(api_key,ioc):
    """
    Queries AbuseIPDB to check if an IP address is reported for abuse.
    """
    api_endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}

    async with aiohttp.ClientSession() as session:
        async with session.get(api_endpoint, headers=headers, params=params) as response:
            result = await response.json()
            pdb.set_trace()
            return result
