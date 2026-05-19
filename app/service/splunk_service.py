import requests
import json
from threading import Thread

SPLUNK_HEC_URL = "https://localhost:8088/services/collector"
SPLUNK_TOKEN = "29207776-57b2-4465-81c9-a71d30d236db"


def _send_to_splunk(payload: dict):
    try:
        headers = {
            "Authorization": f"Splunk {SPLUNK_TOKEN}"
        }

        data = {
            "event": payload
        }

        response = requests.post(
            SPLUNK_HEC_URL,
            headers=headers,
            data=json.dumps(data),
            timeout=2,
            verify=False
        )

        if response.status_code != 200:
            print(f"[SPLUNK][ERROR] Failed: {response.text}")

    except Exception as e:
        print(f"[SPLUNK][EXCEPTION] {str(e)}")


def send_to_splunk_async(payload: dict):
    Thread(target=_send_to_splunk, args=(payload,)).start()