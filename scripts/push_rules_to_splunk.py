import os
import glob
import yaml
import requests

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "34.12.157.61")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/admin/search/saved/searches"

def sync():
    if not SPLUNK_PASSWORD:
        print("[-] Error: SPLUNK_PASSWORD environment variable not set.")
        return
    
    files = glob.glob("splunk-rules/*.yml")
    print(f"[+] Found {len(files)} rules for Splunk.")

    for fpath in files:
        with open(fpath, 'r', encoding='utf-8') as f:
            rule = yaml.safe_load(f)
            rname = rule['name']
            payload = {
                "search": rule['search'],
                "description": rule.get('description', ''),
                "cron_schedule": rule.get('cron_schedule', '*/5 * * * *'),
                "is_scheduled": 1,
                "disabled": rule.get('disabled', 0)
            }
            url = f"{BASE_URL}/{requests.utils.quote(rname)}"
            res = requests.post(url, data=payload, auth=(SPLUNK_USER, SPLUNK_PASSWORD), verify=False)
            
            if res.status_code in [200, 201]:
                print(f"[✅] UPDATED/CREATED: {rname}")
            elif res.status_code == 404:
                payload["name"] = rname
                c_res = requests.post(BASE_URL, data=payload, auth=(SPLUNK_USER, SPLUNK_PASSWORD), verify=False)
                if c_res.status_code in [200, 201]:
                    print(f"[✅] CREATED: {rname}")
                else:
                    print(f"[❌] FAILED TO CREATE {rname}: {c_res.text}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    sync()
