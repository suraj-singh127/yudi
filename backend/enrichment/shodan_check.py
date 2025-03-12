

# Asynchronous function to query Shodan with logging
async def fetch_shodan_data(ioc_type, api, ioc):
    print(f"[INFO] Fetching data for IOC: {ioc} (Type: {ioc_type})")
    try:
        if ioc_type == "IP":
            data = api.host(ioc)
        elif ioc_type == "URL":
            data = api.dns.domain_info(ioc)
        elif ioc_type == "HASH":
            data = api.search(ioc)
        else:
            print(f"[ERROR] Unsupported IOC type: {ioc}")
            return {"ioc": ioc, "error": "Unsupported IOC type"}
        print(f"[SUCCESS] Data fetched successfully for {ioc}")
        return {"ioc": ioc, "data": data}
    except Exception as e:
        print(f"[ERROR] Failed to fetch data for {ioc}: {e}")
        return {"ioc": ioc, "error": str(e)}