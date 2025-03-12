<<<<<<< Updated upstream
from quart import Quart, jsonify
import json
from quart_cors import cors

app = Quart(__name__)
app = cors(app,allow_origin="*")
=======
from quart import Quart, jsonify,request
import json
from quart_cors import cors
from elastic import elastic_io
import os
import dotenv
from elasticsearch import Elasticsearch
from scraping import scraper_con
import time
from typing import Dict,List
from elastic import es_test
from elastic import elastic_io

dotenv.load_dotenv()

app = Quart(__name__)

# Load values from environment variables (Recommended)
ELASTICSEARCH_URL = os.getenv("ELASTIC_URL")
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME")  # Default user
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")  # Should be set in env
CA_CERT_PATH = os.getenv("ELASTIC_CA_CERT")

print(ELASTICSEARCH_URL)
print(ELASTIC_PASSWORD)
print(CA_CERT_PATH)

# Create Elasticsearch client instance with authentication and SSL certificate verification
es = Elasticsearch(
    ELASTICSEARCH_URL,
    http_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
    scheme="https",
    port=9200,
    verify_certs=True,  # Ensures certificate verification
    ca_certs=CA_CERT_PATH,  # Uses CA certificate for SSL verification
)

@app.after_request
async def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response
>>>>>>> Stashed changes

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

<<<<<<< Updated upstream
if __name__ == "__main__":
=======
@app.route('/api/manual_input' , methods=['POST'])
async def testing_post():
    try:
        data = await request.json
        print(f"Data recieved from frontend",data)
        url = data.get("manual_input")
        print(url)
        if not url:
            return jsonify({"error": "No URLs provided"}), 400
        
        # Calling scraping script to scrape the url
        scraper_con.scrape_single_source(url,es)

        return jsonify({"success" : "Successfully scraped and indexed IOCs to Elastic Search"})
    
    finally:
        return jsonify( {"error" : "error getting data from frontend "})
    

@app.route("/api/test")
async def test():
    return {"message": "Backend is working!"}

@app.route("/api/es/testing_es")
async def get_indices():
    if elastic_io.test_elasticsearch_connection(es):
        response = elastic_io.get_all_indexes(es)
        print("Indices fetched : ")
        return response, 200
    else:
        return jsonify({"error" : "error fetching records from ES"}),403

@app.route('/api/scrape', methods=['POST'])
async def scrape():
    print("Right on target...")
    try:
        # Get URLs from the request body (JSON format)
        data = await request.json
        urls = data.get("urls", [])
        print(f"URLs recieved for scraping -  {urls}")
        
        if not urls:
            return jsonify({"error": "No URLs provided"}), 400

        # Call the scrape_job function to process the URLs
        #classified_iocs = scraper_con.scrape_iocs_from_urls(urls,es)
        
        # Optionally, you can save the result to a file
        scraper_con.scrape_job(urls, es)

        return jsonify({"success" : "Successfully scraped and indexed IOCs to Elastic Search"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fetch", methods=["POST"])
async def fetch_index_data():
    """Handle POST request to fetch all indexed data from Elasticsearch."""
    try:
        data = await request.json
        index_name = data.get("index_name")

        if not index_name:
            return jsonify({"error": "Index name is required"}), 400

        result = elastic_io.fetch_all_data(index_name,es)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Function to store results in Elasticsearch
def store_in_elasticsearch(url: str, iocs: Dict[str, List],index_name):
    try:
        doc = {
            "url": url,
            "timestamp": time.time(),
            "iocs": iocs
        }
        es.index(index=index_name, document=doc)
        print(f"Stored IOC data for {url} in Elasticsearch")
    except Exception as e:
        print(f"Error storing in Elasticsearch: {e}")

# Initialize and create index on startup
@app.before_serving
async def startup():
    print("Quart app is starting. Creating necessary Elasticsearch index...")

if __name__ == "__main__":
    #es_test.testing_elasticsearch()
>>>>>>> Stashed changes
    app.run(host="0.0.0.0",port=5000,debug=True)
