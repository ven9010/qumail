import requests

def fetch_quantum_key():
    try:
        response = requests.get("http://127.0.0.1:5001/get_key")
        response.raise_for_status()
        data = response.json()
        return data["key"], data["key_id"]
    except requests.RequestException as e:
        raise Exception(f"Failed to fetch key: {e}")