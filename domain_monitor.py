"""
Thank You to https://github.com/HG-ha/ICP_Query and OpenAI ChatGPT
ICP备案查询: https://github.com/HG-ha/ICP_Query
Docker Hub: https://hub.docker.com/r/yiminger/ymicp/tags

# 拉取镜像
docker pull yiminger/ymicp:yolo8_latest
# 运行并转发容器16181端口到本地所有地址
docker run -d -p 16181:16181 yiminger/ymicp:yolo8_latest

http://0.0.0.0:16181/query/{type}?search={name}
curl http://127.0.0.1:16181/query/web?search=baidu.com

# Install all necessary Python Module or Package
pip install requests python-whois pymongo

# Will use cronjob in Linux to repeat (Every 6 Hours execute below script - sudo crontab -e)
0 */6 * * * /usr/bin/python3 /backup/domain_monitor.py >> /backup/domain_monitor_logfile.log 2>&1

# Access MongoDB on Docker
docker exec -it <MONGODB_DOCKER_ID> bash
mongo -u username -p password

"""

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
DOMAINS_TO_MONITOR = ["", "", ""]  # Only will be use when FILE_PATH can't be found
SUBDOMAINS_TO_CHECK = ["", "", "", "", ""]  # Subdomains to check for SSL certificates
FILE_PATH = "/domain_monitoring/domain_monitor.txt"  # File containing domains to monitor
ICP_URL = "http://127.0.0.1:16181/query/web?search={}"  # Replace with your ICP query service URL
MAX_RETRIES = 8

# Alert Days Confguration
DOMAIN_ALERT_DAYS_THRESHOLD = 30  # Number of days before expiry to trigger an alert
SSL_ALERT_DAYS_THRESHOLD = 5  # Number of days before expiry to trigger an alert

# Email Configuration
EMAIL_RECEIVERS = ["", "", "", "", ""]
SMTP_SERVER = ""
SMTP_PORT = 587
SMTP_USER = ""
SMTP_PASSWORD = ""

# MongoDB Configuration
MONGO_URI = "mongodb://username:password@localhost:27017"
MONGO_DB = "domain_monitoring"
MONGO_COLLECTION = "domain_data"

# Telegram Configuration
TELEGRAM_BOT_TOKEN = ""  # Replace with your bot's API token
TELEGRAM_CHAT_ID = ""  # Replace with your chat or group ID

# Slack Configuration
SLACK_WEBHOOK_URL = ""

def fetch_icp_info_with_retries(domain):
    """Fetch ICP license information for a domain with retries."""
    for attempt in range(MAX_RETRIES):
        try:
            #print(f"Attempt {attempt + 1} to fetch ICP info for domain: {domain}")
            response = requests.get(ICP_URL.format(domain), timeout=20)
            response.raise_for_status()
            data = response.json()

            # Parse ICP data
            main_license, service_license, unit_name, update_record_time = parse_icp_data(data)
            if main_license and service_license:
                print(f"ICP License found on attempt {attempt + 1} for domain: {domain}")
                print(f"Unit_Name: {unit_name}, Update_Record_Time: {update_record_time}, Main_Licence: {main_license}, Service_Licence: {service_license}")
                return main_license, service_license, unit_name, update_record_time
            
            #print(f"No ICP license found on attempt {attempt + 1} for domain: {domain}")

        except requests.RequestException as e:
            print(f"Error on attempt {attempt + 1} for domain {domain}: {e}")

    print(f"WARNING - Invalid  ICP License for domain: {domain}, all {max_retries} attempts failed.")
    return None, None, None, None

def parse_icp_data(data):
    """Parse the ICP data to check for licenses."""
    icp_list = data.get("params", {}).get("list", [])
    if not icp_list:
        return None, None, None, None  # No license found
    icp_info = icp_list[0]
    main_license = icp_info.get("mainLicence")
    service_license = icp_info.get("serviceLicence")
    unit_name = icp_info.get("unitName")
    update_record_time = icp_info.get("updateRecordTime")
    return main_license, service_license, unit_name, update_record_time

def check_domain_expiry(domain):
    """Fetch domain expiry date using WHOIS with retries."""
    for attempt in range(MAX_RETRIES):
        try:
            domain_info = whois.whois(domain)
            expiry_date = domain_info.expiration_date
            if isinstance(expiry_date, list):  # Handle cases where multiple dates are returned
                expiry_date = expiry_date[0]
            if expiry_date:
                days_left = (expiry_date - datetime.now()).days
                print(f"Domain expiry found on attempt {attempt + 1} for domain: {domain}")
                return expiry_date, days_left
            else:
                return None, None
        except Exception as e:
            print(f"Error checking expiry for {domain}: {e}")

    print(f"WARNING - Can't obtain Domain Expiry for domain: {domain}, all {max_retries} attempts failed.")
    return None, None

def check_ssl_certificate(domain, subdomain):
    """Fetch SSL certificate expiration date for a subdomain."""
    full_domain = f"{subdomain}.{domain}"
    for attempt in range(MAX_RETRIES):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((full_domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=full_domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                    days_left = (expiry_date - datetime.now()).days
                    print(f"Domain SSL expiry found on attempt {attempt + 1} for domain: {domain}")
                    return expiry_date, days_left
        except Exception as e:
            print(f"Error checking SSL certificate for {full_domain}: {e}")
    
    print(f"WARNING - Can't obtain SSL Expiry for domain: {domain}, all {max_retries} attempts failed.")
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

def send_slack_alert(message):
    """Send a notification to a Slack channel."""
    payload = {"text": message}
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            print("Slack alert sent successfully.")
        else:
            print(f"Failed to send Slack alert: {response.text}")
    except Exception as e:
        print(f"Error sending Slack alert: {e}")

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
    """Send an alert via email, Telegram and Slack."""
    full_message = f"{subject}\n\n{message}"
    send_email_alert(subject, message)  # Email notification
    send_telegram_alert(full_message)  # Telegram noitification
    #send_slack_alert(full_message)  # Slack notification

def save_to_mongo(data):
    try:
        client = MongoClient(MONGO_URI)
        db = client[MONGO_DB]
        collection = db[MONGO_COLLECTION]
        collection.insert_one(data)
        print(f"Data saved to MongoDB for domain: {data['domain']}")
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

        # Get the date 1 month ago (30 Days)
        one_month_ago = datetime.now() - timedelta(days=1)
        
        # Delete documents where 'checked_at' is older than 1 month
        result = collection.delete_many({"checked_at": {"$lt": one_month_ago}})

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
        print(f"Checking ICP info for domain: {domain}")
        
        # Fetch ICP information with retries
        main_license, service_license, unit_name, update_record_time = fetch_icp_info_with_retries(domain)
        if not main_license or not service_license:
            print(f"WARNING - No ICP license found for {domain}")
            send_alert(
                f"ALERT - No ICP license found for {domain}",
                f"The domain {domain} does not have a valid ICP license."
            )
        else:
            print(f"Domain {domain} has valid ICP licenses.")
        
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
        ssl_info = []
        for subdomain in SUBDOMAINS_TO_CHECK:
            print(f"Checking SSL certificate for subdomain: {subdomain}.{domain}")
            ssl_expiry_date, ssl_days_left = check_ssl_certificate(domain, subdomain)
            ssl_info.append({
                "domain": domain,
                "subdomain": subdomain,
                "ssl_expiry_date": ssl_expiry_date,
                "ssl_days_left": ssl_days_left
            })
            if ssl_expiry_date:
                if ssl_days_left < SSL_ALERT_DAYS_THRESHOLD:
                    print(f"WARNING - SSL Certificate expiring soon for {domain}")
                    send_alert(
                        f"ALERT - SSL Certificate expiring soon: {subdomain}.{domain}",
                        f"The SSL certificate for {subdomain}.{domain} will expire on {ssl_expiry_date} ({ssl_days_left} days remaining)."
                    )
                print(f"Subdomain: {subdomain}.{domain}, SSL Expiry Date: {ssl_expiry_date}, SSL Days Left: {ssl_days_left}")
            else:
                send_alert(
                    f"Unable to determine SSL certificate expiry for {subdomain}.{domain}",
                    f"Failed to fetch the SSL certificate expiry for {subdomain}.{domain}."
                )

        # Save data to MongoDB
        data = {
            "domain": domain,
            "checked_at": current_datetime,
            "icp_info": {
                "main_license": main_license,
                "service_license": service_license,
                "unit_name": unit_name,
                "update_record_time": update_record_time,
            },
            "whois_info": {
                "expiry_date": expiry_date,
                "days_left": days_left,
            },
            "ssl_info": ssl_info,
        }
        save_to_mongo(data)
    delete_old_mongo()


# Run the monitoring script
if __name__ == "__main__":
    monitor_domains()
