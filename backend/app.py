from quart import Quart, jsonify
import json
from quart_cors import cors

app = Quart(__name__)
app = cors(app,allow_origin="*")

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

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)
