import logging
from datetime import datetime
import requests
import whois
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration from environment variables
CONFIG = {
    "domains": ["domain1.com", "domain2.com", "domain3.com"],
    "file_path": "domain_monitor.txt",
    "icp_url": "http://127.0.0.1:16181/query/web?search={}",
    "alert_days_threshold": 14,
    "email_receivers": ["a@example.com"],
    "smtp_server": "mail.example.com",
    "smtp_port": 587,
    "smtp_user": "xyz@example.com",
    "smtp_password": "your_password@",
    "icp_retry_count": 5,
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Domain:
    def __init__(self, name):
        self.name = name
        self.main_license = None
        self.service_license = None
        self.unit_name = None
        self.update_record_time = None
        self.expiry_date = None
        self.days_left = None

    def fetch_icp_info(self):
        for attempt in range(CONFIG["icp_retry_count"]):
            try:
                response = requests.get(CONFIG["icp_url"].format(self.name), timeout=10)
                response.raise_for_status()
                data = response.json()
                self.main_license, self.service_license, self.unit_name, self.update_record_time = self.parse_icp_data(data)
                if self.main_license and self.service_license:
                    logging.info(f"ICP License found for domain: {self.name} on attempt {attempt + 1}")
                    return
                logging.warning(f"No ICP license found on attempt {attempt + 1} for domain: {self.name}")
            except requests.RequestException as e:
                logging.error(f"Failed to fetch ICP info for {self.name} on attempt {attempt + 1}: {e}")
        logging.error(f"All attempts failed for domain: {self.name}")

    def parse_icp_data(self, data):
        icp_list = data.get("params", {}).get("list", [])
        if not icp_list:
            return None, None, None, None
        icp_info = icp_list[0]
        return (icp_info.get("mainLicence"), 
                icp_info.get("serviceLicence"), 
                icp_info.get("unitName"), 
                icp_info.get("updateRecordTime"))

    def check_expiry(self):
        try:
            domain_info = whois.whois(self.name)
            self.expiry_date = domain_info.expiration_date
            if isinstance(self.expiry_date, list):
                self.expiry_date = self.expiry_date[0]
            if self.expiry_date:
                self.days_left = (self.expiry_date - datetime.now()).days
        except Exception as e:
            logging.error(f"Error checking expiry for {self.name}: {e}")

def send_email_alert(subject, message):
    msg = MIMEMultipart()
    msg['From'] = CONFIG["smtp_user"]
    msg['To'] = ", ".join(CONFIG["email_receivers"])
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    try:
        with smtplib.SMTP(CONFIG["smtp_server"], CONFIG["smtp_port"]) as server:
            server.starttls()
            server.login(CONFIG["smtp_user"], CONFIG["smtp_password"])
            server.send_message(msg)
        logging.info(f"Alert email sent successfully with the Subject: {subject}")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def monitor_domains():
    domains = []
    try:
        with open(CONFIG["file_path"], 'r') as file:
            domains = [Domain(line.strip()) for line in file.readlines()]
    except FileNotFoundError:
        logging.error(f"Error: {CONFIG['file_path']} file not found. Using default domains.")
        domains = [Domain(domain) for domain in CONFIG["domains"]]

    for domain in domains:
        domain.fetch_icp_info()
        domain.check_expiry()

        if not domain.main_license or not domain.service_license:
            send_email_alert(f"No ICP license found for {domain.name}", f"The domain {domain.name} does not have a valid ICP license.")
        else:
            logging.info(f"Domain {domain.name} has valid ICP licenses.")

        if domain.expiry_date:
            if domain.days_left < CONFIG["alert_days_threshold"]:
                send_email_alert(f"Domain expiring soon: {domain.name}", f"The domain {domain.name} will expire on {domain.expiry_date} ({domain.days_left} days remaining).")
            logging.info(f"Domain: {domain.name}, Expiry Date: {domain.expiry_date}, Days Left: {domain.days_left}")
        else:
            send_email_alert(f"Unable to determine expiry for {domain.name}", f"WHOIS lookup failed to find the expiry date for {domain.name}.")
            logging.warning(f"Could not determine expiry for {domain.name}")

if __name__ == "__main__":
    monitor_domains()
