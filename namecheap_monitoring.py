import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

# NameCheap API credentials
API_USER = "xxxxxx"
API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxx"
USERNAME = "xxxxxx"
CLIENT_IP = "xxx.xxx.xxx.xxx"
NAMECHEAP_API_URL = "https://api.namecheap.com/xml.response"

# Telegram Bot credentials
TELEGRAM_BOT_TOKEN = "xxxxxxxx:xxxxxxxxxxxxxxxxxxx"  # Replace with your bot's API token
TELEGRAM_CHAT_ID = "xxxxxxx"  # Replace with your chat or group ID

# Define a threshold for domain expiration warnings (in days)
EXPIRATION_THRESHOLD = 30

def get_domains_from_namecheap():
    """Fetch domain list from NameCheap."""
    params = {
        "ApiUser": API_USER,
        "ApiKey": API_KEY,
        "UserName": USERNAME,
        "ClientIp": CLIENT_IP,
        "Command": "namecheap.domains.getList",
        "PageSize": 100,
    }
    response = requests.get(NAMECHEAP_API_URL, params=params)
    if response.status_code != 200:
        raise Exception(f"Error fetching domains: {response.text}")

    # Parse the XML response
    root = ET.fromstring(response.content)

    # Extract namespace from the root element
    namespace = {'ns': root.tag.split('}')[0].strip('{')}

    # Find all domains in the response
    domains = []
    for domain in root.findall(".//ns:Domain", namespace):
        name = domain.attrib.get("Name")
        expires = domain.attrib.get("Expires")
        autoRenew = domain.attrib.get("AutoRenew")
        domains.append({"name": name, "expires": expires, "autoRenew": autoRenew})
    return domains

def send_telegram_message(message):
    """Send a message via Telegram."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        raise Exception(f"Error sending message: {response.text}")

def check_expiring_domains(domains):
    """Check if any domains are expiring soon and send alerts."""
    today = datetime.now()
    alert_message = "🚨 Domain Expiry Alert 🚨\n\n"
    alerts = []

    for domain in domains:
        expiry_date = datetime.strptime(domain["expires"], "%m/%d/%Y")
        days_to_expiry = (expiry_date - today).days
        if domain['name'] == "google.com":
            continue
        if days_to_expiry <= EXPIRATION_THRESHOLD:
            print(f"{domain['name']} is expiring in {days_to_expiry} days (on {domain['expires']}).")
            alerts.append(f"{domain['name']} is expiring in {days_to_expiry} days (on {domain['expires']}).")

    if alerts:
        alert_message += "\n".join(alerts)
        send_telegram_message(alert_message)
    else:
        print(f"No domain from Namecheap going to expire.")

if __name__ == "__main__":
    try:
        today = datetime.now()
        print(f"\nChecking Namecheap Domain Expiry now {today}")
        domains = get_domains_from_namecheap()
        check_expiring_domains(domains)
    except Exception as e:
        send_telegram_message(f"Error: {e}")
