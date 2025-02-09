import aiohttp
import pdb

pdb.set_trace()

async def check_urlhaus(api_key,ioc):
    """
    Queries URLHaus API to check if a given URL is blacklisted.
    """
    api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {"Auth-Key" : api_key}
    data = {"url": ioc }

    async with aiohttp.ClientSession() as session:
        async with session.post(api_endpoint,headers=headers, data=data) as response:
            results = await response.json()
            
            pdb.set_trace()
            print(results)
            return await results

