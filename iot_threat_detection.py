import cohere
import datetime
import mailtrap as mt
import random
import requests
import re
import time
import uuid
import json
import logging
import ipaddress
import os


from urllib.parse import urlparse
from pymisp import PyMISP, MISPEvent, MISPAttribute
from dotenv import load_dotenv


load_dotenv()

# Misp configuration
MISP_URL = "https://192.168.1.63/"
MISP_API_KEY = os.getenv('MISP_API_KEY')

# Initialize misp
misp = PyMISP(MISP_URL, MISP_API_KEY, ssl=False)


# For cohere api
cohere_api_key = os.getenv('COHERE_API_KEY')

# Mailtrap configuration
mailtrap_token = os.getenv('MAILTRAP_TOKEN')
recipient = 'funyaq@mailto.plus'

# Set up logging
logging.basicConfig(level=logging.INFO)


def create_misp_event(log):
    """Create a MISP event from the log."""
    
    event = MISPEvent()
    event_info = f"Alert: {log['alert']['signature']} from {log['src_ip']} to {log['dest_ip']}"

    # Set event properties
    event.info = event_info
    event.org_id = "1"
    event.orgc_id = "1"
    event.distribution = "0"
    event.sharing_group_id = "1"
    event.proposal_email_lock = True
    event.locked = True
    event.threat_level_id = str(log['alert']['severity'])
    event.disable_correlation = False
    event.event_creator_email = "prof.addy98@gmail.com"
    event.date = log['timestamp']

    result = misp.add_event(event, pythonify=True)
 
    return result


def add_attributes_to_event(event, log):
    """Add attributes to a MISP event based on a log entry."""
    
    # Extract relevant information from the log
    src_ip = log['src_ip']
    dest_ip = log['dest_ip']
    src_port = log['src_port']
    dest_port = log['dest_port']
    protocol = log['proto']
    http_info = log.get('http', {})
    
    # Add source IP
    event.add_attribute(
        category="Network activity",
        type="ip-src",
        value=src_ip,
        comment="Source IP of the alert"
    )

    # Add destination IP
    event.add_attribute(
        category="Network activity",
        type="ip-dst",
        value=dest_ip,
        comment="Destination IP of the alert"
    )

    # Add source port
    event.add_attribute(
        category="Network activity",
        type="port",  # Changed from port-src to port
        value=str(src_port),
        comment="Source port of the alert"
    )

    # Add destination port
    event.add_attribute(
        category="Network activity",
        type="port",  # Changed from port-dst to port
        value=str(dest_port),
        comment="Destination port of the alert"
    )

    # Add protocol
    event.add_attribute(
        category="Network activity",
        type="text",
        value=protocol,
        comment="Protocol used in the alert"
    )

    # Add HTTP details if available
    if http_info:
        if 'url' in http_info:
            event.add_attribute(
                category="Network activity",
                type="url",
                value=http_info['url'],
                comment="HTTP URL accessed"
            )

        if 'http_user_agent' in http_info:
            event.add_attribute(
                category="Network activity",
                type="text",
                value=http_info['http_user_agent'],
                comment="User agent of the HTTP request"
            )

    # Update the event in MISP
    result = misp.update_event(event)
    return result


def generate_mitigation_info(log):
    """Generate mitigation info by sendind the log entry to the LLM"""

    co = cohere.Client(cohere_api_key)
    prompt = f"Explain the following log entry and provide mitigation steps as to a layman:\n\n{log}"
    response = co.generate(
        model='command-xlarge-nightly',
        prompt=prompt,
    )

    return response.generations[0].text


def send_email(subject, body):
    """Send an email with the given subject and body."""

    mail = mt.Mail(
        sender=mt.Address(email="mailtrap@demomailtrap.com", name="Action Required: "),
        to=[mt.Address(email=recipient)],
        subject=subject,
        text=body,
        category="Integration Test",
    )
    client = mt.MailtrapClient(token=mailtrap_token)

    response = client.send(mail)
    print(response)  # {'success': True, 'message_ids': ['4cf9e4f0-183a-11ef-0000-f18fdd699b42']}
    return response


def fetch_iocs():
    """Fetch IoCs from MISP instance"""

    events = misp.search(controller='events', return_format='json', published=True)
    iocs = set()

    if isinstance(events, list) and len(events) > 0:
        for event in events:
            event_data = event.get('Event')
            if event_data:
                attributes = event_data.get('Attribute', [])
                for attr in attributes:
                    if attr['type'] in ['ip-src', 'domain', 'url']:
                        iocs.add(attr['value'])
    return iocs


def sid_generator():
    sid = 999
    while True:
        sid += 1
        yield sid


def create_suricata_rules_with_iocs(iocs, output_file='/var/lib/suricata/rules/misp.rules'):
    """Create suricata rules"""

    sid_gen = sid_generator()
    with open(output_file, "a") as f:
        for ioc in iocs:
            if ioc.count('.') == 3:  # Check if it's an IP address
                # SSH Brute-Force Rule
                f.write(f"""drop tcp {ioc} any -> any 22 (msg:"IoC: Potential SSH Brute Force Attack"; flow:to_server,established; content:"Failed password"; nocase; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:{next(sid_gen)}; rev:1;)\n""")
                # DoS Attack Rule
                f.write(f"""drop ip {ioc} any -> any any (msg:IoC: "Potential DoS Attack Detected"; threshold:type threshold, track by_src, count 100, seconds 10; classtype:network-flood; sid:{next(sid_gen)}; rev:1;)\n""")
                f.write(f"""drop ip {ioc} any -> $HOME_NET any (msg:"IoC: Malicious IP Detected"; sid:{hash(ioc) + 1}; rev:1;)""")
            else:  
                # DNS Blocking Rule
                f.write(f"drop dns any any -> any any (msg:\"IoC: Blocked malicious DNS query for {ioc}\"; content:\"{ioc}\"; dns_query; sid:{next(sid_gen)}; rev:1;)\n")
    return "Suricata rules generated successfully."


def is_high_priority_alert(log, min_severity=2):
    """Check if the log is a high-priority alert based on severity."""
    
    if log.get('event_type') == 'alert':
        alert = log.get('alert', {})
        severity = alert.get('severity')
        category = alert.get('category')

        if category != 'Not Suspicious Traffic':
            return severity is not None and int(severity) >= min_severity
    return False


def fetch_suricata_logs_with_higher_priority(file_path='/var/log/suricata/eve.json', min_severity=2):
    """Fetch logs from suricata log file to create MISP event"""
    high_priority_logs = []
    seen_keys = set()  # To track unique (src_ip, signature) pairs

    with open(file_path) as f:
        for line in f:
            try:
                log = json.loads(line.strip())
                if is_high_priority_alert(log, min_severity):
                    # Create a unique key based on src_ip and alert signature
                    src_ip = log.get('src_ip')
                    alert_signature = log['alert'].get('signature')
                    unique_key = (src_ip, alert_signature)

                    # Check if the unique key has already been seen
                    if unique_key not in seen_keys:
                        seen_keys.add(unique_key)  # Add the unique key to the set
                        high_priority_logs.append(log)  # Add the log to the list
            except json.JSONDecodeError:
                # Skip lines that are not valid JSON
                continue

    return high_priority_logs


if __name__ == "__main__":
    # For IoCs
    iocs = fetch_iocs()

    rules = create_suricata_rules_with_iocs(iocs)
    print(rules)

    logs = fetch_suricata_logs_with_higher_priority()

    for i, log in enumerate(logs):
        # print(f"log {i}. {log}\n")
        
        # Create MISP event and add attributes
        event = create_misp_event(log)
        updated_event = add_attributes_to_event(event, log)

        # generate_iot_logs()
        mitigation = generate_mitigation_info(log)
        send_email(subject=event['info'], body=mitigation)