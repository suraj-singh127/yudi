import requests
import time

# Function to check Quart backend service
def check_quart_backend():
    try:
        response = requests.get("http://localhost:5000/api/test")
        if response.status_code == 200:
            print("✅ Quart backend is up and running!")
        else:
            print(f"❌ Quart backend is not available! Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to Quart backend: {e}")

# Function to check Vite frontend service
def check_vite_frontend():
    try:
        response = requests.get("http://localhost:5173/")
        if response.status_code == 200:
            print("✅ Vite frontend is up and running!")
        else:
            print(f"❌ Vite frontend is not available! Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to Vite frontend: {e}")

# Health check function for all services
def health_check():
    print("🔹 Starting health checks...\n")
    
    check_quart_backend()
    time.sleep(1)  # Add some delay before checking the next service
    
    check_vite_frontend()

if __name__ == "__main__":
    health_check()
