import os
import httpx as requests
import json

GRAFANA_URL = "http://localhost:3000"
AUTH = ("admin", "iShowSpeed")
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitoring", "grafana")

def make_dirs():
    os.makedirs(os.path.join(BASE_DIR, "dashboards"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "provisioning", "datasources"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "provisioning", "dashboards"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "provisioning", "alerting"), exist_ok=True)

def write_yaml(path, content):
    with open(path, "w") as f:
        f.write(content)

def export_dashboards():
    r = requests.get(f"{GRAFANA_URL}/api/search?type=dash-db", auth=AUTH)
    r.raise_for_status()
    dashboards = r.json()
    
    for dash in dashboards:
        uid = dash["uid"]
        title = dash["title"].replace(" ", "_").lower()
        print(f"Exporting dashboard: {title} ({uid})")
        
        r_dash = requests.get(f"{GRAFANA_URL}/api/dashboards/uid/{uid}", auth=AUTH)
        r_dash.raise_for_status()
        dash_data = r_dash.json()["dashboard"]
        
        # Remove ID to make it portable
        dash_data.pop("id", None)
        
        with open(os.path.join(BASE_DIR, "dashboards", f"{title}.json"), "w") as f:
            json.dump(dash_data, f, indent=2)

def export_alert_rules():
    print("Exporting alert rules...")
    r = requests.get(f"{GRAFANA_URL}/api/v1/provisioning/alert-rules", auth=AUTH)
    if r.status_code == 200:
        rules = r.json()
        if rules:
            with open(os.path.join(BASE_DIR, "provisioning", "alerting", "alerts.json"), "w") as f:
                json.dump({"apiVersion": 1, "groups": [{"orgId": 1, "name": "Main", "folder": "Alerts", "interval": "1m", "rules": rules}]}, f, indent=2)
            print("Alert rules exported.")
        else:
            print("No alert rules found.")
    else:
        print(f"Failed to export alert rules: {r.status_code}")

def create_provisioning_files():
    datasource_yaml = """apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
"""
    write_yaml(os.path.join(BASE_DIR, "provisioning", "datasources", "prometheus.yml"), datasource_yaml)

    dashboards_yaml = """apiVersion: 1

providers:
  - name: 'Default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
"""
    write_yaml(os.path.join(BASE_DIR, "provisioning", "dashboards", "dashboards.yml"), dashboards_yaml)

if __name__ == "__main__":
    make_dirs()
    create_provisioning_files()
    export_dashboards()
    # Exporting alerts via API
    export_alert_rules()
    print("Export complete!")
