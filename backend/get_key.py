import json

JSON_FILE = "api_keys.json"  # The JSON file containing API keys

def extract_platform_keys(platform, json_file=JSON_FILE):
    """Extracts API keys for a given platform from a JSON file."""
    try:
        with open(json_file, "r") as file:
            api_keys = json.load(file)  # Load the JSON data
        
        # Check if the platform exists in the JSON data
        if platform in api_keys:
            return api_keys[platform]  # Return the keys for the platform
        else:
            return f"Error: No API keys found for platform '{platform}'"

    except FileNotFoundError:
        return f"Error: JSON file '{json_file}' not found."
    except json.JSONDecodeError:
        return f"Error: JSON file '{json_file}' is not properly formatted."

