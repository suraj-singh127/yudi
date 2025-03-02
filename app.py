from quart import Quart, jsonify
import json

app = Quart(__name__)

JSON_FILE_PATH = "report.json"  # Path to the JSON file

@app.route('/get_ioc')
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
    app.run(debug=True)
