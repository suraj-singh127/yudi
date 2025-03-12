from elasticsearch import SSLError

def test_elasticsearch_connection(es):
    """
    Tests connectivity to an Elasticsearch instance using CA cert, password, and URL.
    Returns a success message if the connection is successful, else prints the error.
    """
    try:
        # Perform a simple ping request to check connectivity
        if es.ping():
            print("✅ Successfully connected to Elasticsearch!")
            # Get and print basic cluster information
            cluster_info = es.info()
            print("🔹 Cluster Info:", cluster_info.get("cluster_name"))
            return True
        else:
            print("❌ Failed to connect to Elasticsearch!")
            return False

    except SSLError:
        print("❌ SSL Error: Check your CA certificate path.")
    except ConnectionError:
        print("❌ Connection Error: Elasticsearch may not be running.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    return False

# Function to get a list of all indexes in the Elasticsearch cluster
def get_all_indexes(es):
    """Get all indexes from Elasticsearch in JSON format."""
    try:
        # Use the _cat/indices API with format=json
        response = es.cat.indices(format="json")
        print(response)
        
        if response:
            return response
        else:
            print("[ℹ️] No indexes found.")
            return []
    except Exception as e:
        print(f"[❌] Error fetching indexes: {e}")
        return []

def fetch_all_data(index_name,es):
    
    """Fetch all documents from the specified Elasticsearch index."""
    try:
        query = {
            "query": {
                "match_all": {}  # Fetch all documents
            }
        }

        # Scroll API for fetching all documents (used for large datasets)
        scroll_time = "2m"  # Keep the scroll context alive for 2 minutes
        batch_size = 1000  # Number of documents to fetch per request

        # Initial search request
        response = es.search(index=index_name, body=query, scroll=scroll_time, size=batch_size)

        # Extract the scroll ID and initial batch of hits
        scroll_id = response["_scroll_id"]
        hits = response["hits"]["hits"]

        all_docs = hits

        # Keep scrolling while more documents are available
        while len(hits) > 0:
            response = es.scroll(scroll_id=scroll_id, scroll=scroll_time)
            hits = response["hits"]["hits"]
            all_docs.extend(hits)

        # Clean up the scroll context
        es.clear_scroll(scroll_id=scroll_id)

        return all_docs

    except Exception as e:
        print(f"Error fetching data from Elasticsearch: {e}")
        return None

