import aiohttp
import pdb

async def check_virustotal(api_key,ioc):
    """
    Queries VirusTotal API to check a URL for threats.
    """
    api_endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key,
               'content-type': 'application/x-www-form-urlencoded'
               }
    data = {"url": ioc}

    

    async with aiohttp.ClientSession() as session:
        async with session.post(api_endpoint, headers=headers, data=data) as response:
            result = await response.json()
            
            pdb.set_trace()
            
            return result 
        
async def search_virus_total(api_key, ioc):

    api_endpoint = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {
    "accept": "application/json",
    "x-apikey": api_key,
    "content-type": "application/x-www-form-urlencoded"
    }
    print(f"Fetching data from \n Endpoint : {api_endpoint} \n Headers - {headers} for {ioc}.........")

    async with aiohttp.ClientSession() as session:
        async with session.get(api_endpoint, headers=headers) as response:
            result = await response.json()
            pdb.set_trace()
            return result 
