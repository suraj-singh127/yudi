import os
import dotenv
from elasticsearch import Elasticsearch
from elasticsearch import SSLError

dotenv.load_dotenv()

# Load values from environment variables (Recommended)
ELASTICSEARCH_URL = os.getenv("ELASTIC_URL")
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME")  # Default user
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")  # Should be set in env
CA_CERT_PATH = os.getenv("ELASTIC_CA_CERT")
INDEX = "test_index"

# Connect to Elasticsearch
es = Elasticsearch(
    ELASTICSEARCH_URL,
    http_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
    scheme="https",
    port=9200,
    verify_certs=True,  # Ensures certificate verification
    ca_certs=CA_CERT_PATH,  # Uses CA certificate for SSL verification
)

# Sample document for testing
test_doc = {
    "url": "https://example.com",
    "ioc_type": "malicious_domain",
    "value": "malicious.com",
    "timestamp": "2025-03-08T12:00:00Z"
}

def test_elasticsearch_connection():
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


# Function to create an index (if not exists)
def create_index():
    if not es.indices.exists(index=INDEX):
        es.indices.create(index=INDEX)
        print(f"✅ Index '{INDEX}' created.")
    else:
        print(f"⚠️ Index '{INDEX}' already exists.")


# Function to insert a document
def insert_document(doc_id, document):
    response = es.index(index=INDEX, id=doc_id, document=document)
    print(f"✅ Document inserted with ID '{doc_id}': {response['_id']}")


# Function to get a document by ID
def get_document(doc_id):
    try:
        response = es.get(index=INDEX, id=doc_id)
        print(f"✅ Document retrieved: {response['_source']}")
    except Exception as e:
        print(f"❌ Error retrieving document: {e}")


# Function to update a document
def update_document(doc_id, updated_fields):
    response = es.update(index=INDEX, id=doc_id, doc=updated_fields)
    print(f"✅ Document updated with ID '{doc_id}': {response['result']}")


# Function to delete a document
def delete_document(doc_id):
    response = es.delete(index=INDEX, id=doc_id)
    print(f"✅ Document deleted with ID '{doc_id}': {response['result']}")


# Function to search for documents
def search_documents(query):
    response = es.search(index=INDEX, query=query, size=10)
    if response['hits']['hits']:
        print("✅ Search Results:")
        for hit in response['hits']['hits']:
            print(f" - {hit['_source']}")
    else:
        print("⚠️ No results found for the query.")


# Function to delete the entire index
def delete_index():
    es.indices.delete(index=INDEX, ignore_unavailable=True)
    print(f"✅ Index '{INDEX}' deleted.")


# Run CRUD operations
def testing_elasticsearch():
    test_results = False
    # Testing connectivity to Elasticsearch
    print("\n🔹 Testing Elasticsearch connection...")
    if test_elasticsearch_connection():
        print("\n🔹 Performing CRUD operations...\n")

        doc_id = "1"

        # Step 1: Create index if it doesn't exist
        create_index()

        # Step 2: Insert a document
        insert_document(doc_id, test_doc)

        # Step 3: Retrieve the document
        get_document(doc_id)

        # Step 4: Update the document
        update_document(doc_id, {"ioc_type": "updated_malicious_domain"})

        # Step 5: Search for documents
        search_documents({"match": {"ioc_type": "updated_malicious_domain"}})

        # Step 6: Delete the document
        delete_document(doc_id)

        # Step 7: Delete the index
        delete_index()
        test_results = True
        
    else:
        print("❌ Elasticsearch connection test failed. CRUD operations skipped.")
        test_results = False

    return test_results

