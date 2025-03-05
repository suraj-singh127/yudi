from quart import Quart, jsonify,request
import json
from quart_cors import cors
import aiohttp
from scraper import fetch_content
from extractor import extract_content


app = Quart(__name__)

async def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

JSON_FILE_PATH = "report.json"  # Path to the JSON file

@app.route('/api/consolidated-data')
async def get_ioc():
    """Read the JSON file and return its contents as a response."""
    try:
        with open(JSON_FILE_PATH, "r") as file:
            data = json.load(file)
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({"error": "JSON file not found"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 500

@app.route('/api/scrape', methods=['POST'])
async def scrape_url():
    """API Endpoint to scrape and extract IOCs."""
    data = await request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Fetch content using Selenium
    result = fetch_content(url)

    if "error" in result:
        return jsonify(result), 400  # Return error response

    # Extract meaningful content & IOCs
    extracted = extract_content(result["content"])

    return jsonify({
        "url": url,
        "title": extracted["title"],
        "text_snippet": extracted["text_snippet"],
        "iocs": extracted["iocs"]
    })


@app.route("/api/test")
async def test():
    return {"message": "Backend is working!"}


if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)
