# connectors/shodan_connector.py
import os
from shodan import Shodan
import socket

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
shodan_client = Shodan(SHODAN_KEY) if SHODAN_KEY else None

def scan_host(target):
    data = {"shodan_open_ports": 0, "shodan_vuln_services": 0}
    if not shodan_client:
        return data
    try:
        # resolve domain → IP
        ip = socket.gethostbyname(target)
        host = shodan_client.host(ip)
        ports = host.get("ports", [])
        data["shodan_open_ports"] = len(ports)

        vuln_services = 0
        for item in host.get("data", []):
            if "vuln" in item.get("tags", []):
                vuln_services += 1
        data["shodan_vuln_services"] = vuln_services
    except Exception:
        pass
    return data
