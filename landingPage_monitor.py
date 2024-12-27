import requests
import whois
import ssl
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from pymongo import MongoClient

# Configuration
DOMAINS_TO_MONITOR = ["a.com", "b.com", "c.com", "d.com", "e.com"]  # Only will be use when FILE_PATH can't be found
FILE_PATH = "/domain_monitoring/landingPage_domain_monitor.txt"  # File containing domains to monitor
DOMAIN_ALERT_DAYS_THRESHOLD = 30  # Number of days before expiry to trigger an alert
SSL_ALERT_DAYS_THRESHOLD = 5  # Number of days before expiry to trigger an alert
EMAIL_RECEIVERS = ["a@example.com", "b@example.com", "c@example.com"]
SMTP_SERVER = "example.com"
SMTP_PORT = 587
SMTP_USER = "a@example.com"
SMTP_PASSWORD = ""

# MongoDB Configuration
MONGO_URI = "mongodb://username:password@localhost:27017"
MONGO_DB = "landingPage_monitoring"
MONGO_COLLECTION = "landingPage_data"

# Telegram Configuration
TELEGRAM_BOT_TOKEN = "xxxxx:xxxxxxxxx"  # Replace with your bot's API token
TELEGRAM_CHAT_ID = "xxxxxxx"  # Replace with your chat or group ID

def check_page_status(domain):
    try:
        print(f"Checking https://{domain} landing page status")
        domain = f"https://{domain}"
        response = requests.get(domain, timeout=10)

        if response.status_code != 200:
            print(f"Error: Received HTTP {response.status_code} from {domain}")
            return f"Error: Received HTTP {response.status_code} from {domain}"
        elif response.status_code == 200:
            print(f"OK from {domain}")
            return True
    except requests.Timeout:
        print(f"Timeout error while checking {domain}")
        return f"Timeout error while checking {domain}"
    except requests.RequestException as e:
        print(f"Request error while checking {domain}: {e}")
        return f"Request error while checking {domain}: {e}"

def check_domain_expiry(domain):
    """Fetch domain expiry date using WHOIS."""
    try:
        domain_info = whois.whois(domain)
        expiry_date = domain_info.expiration_date
        if isinstance(expiry_date, list):  # Handle cases where multiple dates are returned
            expiry_date = expiry_date[0]
        if expiry_date:
            days_left = (expiry_date - datetime.now()).days
            return expiry_date, days_left
        else:
            return None, None
    except Exception as e:
        print(f"Error checking expiry for {domain}: {e}")
    return None, None

def check_ssl_certificate(domain):
    """Fetch SSL certificate expiration date for a subdomain."""
    full_domain = f"{domain}"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((full_domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=full_domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                days_left = (expiry_date - datetime.now()).days
                return expiry_date, days_left
    except Exception as e:
        print(f"Error checking SSL certificate for {full_domain}: {e}")
    return None, None

def send_telegram_alert(message):
    """Send a message to a Telegram chat or group."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Telegram alert sent successfully. {message}")
        else:
            print(f"Failed to send Telegram alert: {response.text}")
    except Exception as e:
        print(f"Error sending Telegram alert: {e}")

def send_email_alert(subject, message):
    """Send an email alert to the configured receivers."""
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = ", ".join(EMAIL_RECEIVERS)
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Alert email sent successfully with the Subject: {subject}")
    except Exception as e:
        print(f"Error sending email: {e}")

def send_alert(subject, message):
    """Send an alert via email and Telegram."""
    full_message = f"{subject}\n\n{message}"
    send_email_alert(subject, message)  # Email notification
    send_telegram_alert(full_message)  # Telegram noitification

def save_to_mongo(data):
    try:
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB]
        collection = db[MONGO_COLLECTION]
        collection.insert_one(data)
        print(f"Data saved to MongoDB for domain: {data['domain']}")
        print(f"{data}")
    except Exception as e:
        print(f"Error saving to MongoDB: {e}")

def delete_old_mongo():
    try:
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB]
        collection = db[MONGO_COLLECTION]

        # Check if the index exists, and create it if it doesn't
        if "checked_at_1" not in collection.index_information():
            collection.create_index([("checked_at", 1)])

        # Get the date 3 months ago (90 Days)
        three_months_ago = datetime.now() - timedelta(days=1)
        
        # Delete documents where 'checked_at' is older than 3 months
        result = collection.delete_many({"checked_at": {"$lt": three_months_ago}})

        # Output how many documents were deleted
        print(f"Deleted {result.deleted_count} documents.")
    except Exception as e:
        print(f"Error deleting old MongoDB Data: {e}")

def monitor_domains():
    """Monitor each domain for ICP license and expiration."""
    try:
        # Read domains from the input file
        with open(FILE_PATH, 'r') as file:
            DOMAINS = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"Error: {FILE_PATH} file not found. Will proceed on domain listed in the script.")
        DOMAINS = DOMAINS_TO_MONITOR
        #return

    for domain in DOMAINS:
        current_datetime = datetime.now()

        print("\nCurrent date and time:", current_datetime)
        print(f"Checking Landing Page status for domain: {domain}")
        # Check domain landing page status
        status = check_page_status(domain)
        if status != True or not status:
            print(f"WARNING - Unable to load landing page for {domain}")
            send_alert(
                f"ALERT - Unable to load landing page for {domain}",
                f"The landing page {domain} is unable to load."
            )
            status = "Error"
        else:
            print(f"Landing Page {domain} successful loaded.")
            status = "OK"
        
        # Check domain expiry
        print(f"Checking expiry info for domain: {domain}")
        expiry_date, days_left = check_domain_expiry(domain)
        if expiry_date:
            if days_left < DOMAIN_ALERT_DAYS_THRESHOLD:
                print(f"WARNING - Domain expiring soon for {domain}")
                send_alert(
                    f"ALERT - Domain expiring soon: {domain}",
                    f"The domain {domain} will expire on {expiry_date} ({days_left} days remaining)."
                )
            print(f"Domain: {domain}, Expiry Date: {expiry_date}, Days Left: {days_left}")
        else:
            send_alert(
                f"Unable to determine expiry for {domain}",
                f"WHOIS lookup failed to find the expiry date for {domain}."
            )
            print(f"Could not determine expiry for {domain}")

        # Check subdomain SSL
        print(f"Checking SSL certificate for doamin: {domain}")
        ssl_expiry_date, ssl_days_left = check_ssl_certificate(domain)
        if ssl_expiry_date:
            if ssl_days_left < SSL_ALERT_DAYS_THRESHOLD:
                print(f"WARNING - SSL Certificate expiring soon for {domain}")
                send_alert(
                    f"ALERT - SSL Certificate expiring soon: {domain}",
                    f"The SSL certificate for {domain} will expire on {ssl_expiry_date} ({ssl_days_left} days remaining)."
                )
            print(f"Domain: {domain}, SSL Expiry Date: {ssl_expiry_date}, SSL Days Left: {ssl_days_left}")
        else:
            send_alert(
                f"Unable to determine SSL certificate expiry for {domain}",
                f"Failed to fetch the SSL certificate expiry for {domain}."
            )

        # Save data to MongoDB
        data = {
            "domain": domain,
            "checked_at": current_datetime,
            "landing_page_status_info": {
                "status": status,
            },
            "whois_info": {
                "expiry_date": expiry_date,
                "days_left": days_left,
            },
            "ssl_info": {
                "ssl_expiry_date": ssl_expiry_date,
                "ssl_days_left": ssl_days_left,
            },
        }
        save_to_mongo(data)
    delete_old_mongo()

# Run the monitoring script
if __name__ == "__main__":
    monitor_domains()
