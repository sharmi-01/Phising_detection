#!/usr/bin/env python3

import sys
import email
import re
import enchant
import requests
from datetime import datetime
from collections import Counter
from urllib.parse import urlparse

def calculate_score(email_headers):
   
    weights = {
        'sender_email_address': 20,
        'links_in_email': 25,
        'spf_record_check': 15,
        'dkim_check': 15,
        'dmarc_check': 10,
        'content_analysis': 25,
        'unusual_sending_behavior': 15,
        'reply_to_field': 10,
        'ip_reputation_of_sender': 10
    }

   
    scores = {
        'sender_email_address': 20,
        'links_in_email': 25,
        'spf_record_check': 15,
        'dkim_check': 10,
        'dmarc_check': 25,
        'content_analysis': 15,
        'unusual_sending_behavior': 15,
        'reply_to_field': 10,
        'ip_reputation_of_sender': 10
    }

    
    scores['sender_email_address'] = check_sender_email_address(email_headers, "officialbank.com", "YOUR_VIRUSTOTAL_API_KEY")
    scores['links_in_email'] = check_links_in_email(email_headers, "YOUR_VIRUSTOTAL_API_KEY")
    scores['spf_record_check'] = check_spf_record(email_headers)
    scores['dkim_check'] = check_dkim(email_headers)
    scores['dmarc_check'] = check_dmarc(email_headers)
    scores['content_analysis'] = check_content_analysis(email_headers)
    scores['unusual_sending_behavior'] = check_unusual_sending_behavior(email_headers)
    scores['reply_to_field'] = check_reply_to_field(email_headers)
    scores['ip_reputation_of_sender'] = check_ip_reputation(email_headers, "YOUR_VIRUSTOTAL_API_KEY")

   
    total_score = sum(weights[key] * scores[key] for key in weights)

    
    if total_score <= 20:
        risk_level = 'Likely Safe'
    elif total_score <= 40:
        risk_level = 'Low Risk'
    elif total_score <= 70:
        risk_level = 'Moderate Risk'
    else:
        risk_level = 'High Risk'

    return total_score, risk_level

def check_sender_email_address(email_headers, expected_domain, virustotal_api_key):
    sender_email_score = 0

    
    sender_email = extract_sender_email(email_headers)

    if sender_email:
        
        if extract_domain(sender_email) == expected_domain:
            sender_email_score += 10
            print("Legitimate domain detected.")
        else:
            print("Domain mismatch detected.")

        # Check for display name mismatch
        display_name = extract_display_name(sender_email)
        if display_name:
            if not re.match(r"[A-Za-z\s]+", display_name):  # Adjust the regex pattern as needed
                sender_email_score += 5
                print("Display name mismatch detected.")

        
        domain = extract_domain(sender_email)
        if domain:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                                    headers={"x-apikey": virustotal_api_key})

            if response.status_code == 200:
                data = response.json()
                reputation = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious")

               
                if reputation and int(reputation) > 0:
                    sender_email_score += 5
                    print("Potentially malicious domain detected.")

            else:
                print("Error fetching domain reputation from VirusTotal:", response.status_code)

   
    print("\nSender's Email Address Score:")
    print("- Sender's email address score:", sender_email_score)

   
    return sender_email_score

def extract_sender_email(email_headers):
    for header, value in email_headers:
        if header.lower() == "from":
            match = re.search(r'[\w\.-]+@[\w\.-]+', value)
            if match:
                return match.group()
    return None

def extract_display_name(email):
    match = re.match(r'\"?([A-Za-z\s]+)\"? <[\w\.-]+@[\w\.-]+>', email)
    if match:
        return match.group(1)
    return None

def extract_domain(email):
    match = re.search(r'@([\w\.-]+)', email)
    if match:
        return match.group(1)
    return None

def check_links_in_email(email_headers, virustotal_api_key):
    links_score = 0

   
    links = extract_links(email_headers)

    if links:
       
        num_links = len(links)
        if num_links > 1:
            links_score += 10
            print(f"Numerous links detected: {num_links}")
        elif num_links == 0:
            print("No links detected.")
        else:
            print(f"Single link detected.")

       
        for link in links:
            domain = extract_domain_from_url(link)
            if domain:
                response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                                        headers={"x-apikey": virustotal_api_key})

                if response.status_code == 200:
                    data = response.json()
                    reputation = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious")

                    
                    if reputation and int(reputation) > 0:
                        links_score += 10
                        print(f"Potentially malicious domain detected in link: {link}")

                else:
                    print(f"Error fetching domain reputation from VirusTotal for link: {link}", response.status_code)

        
        for link in links:
            if is_hidden_or_shortened_url(link):
                links_score += 5
                print(f"Hidden or shortened URL detected: {link}")

   
    print("\nLinks in Email Score:")
    print("- Links in email score:", links_score)

   
    return links_score

def extract_links(email_headers):
    links = []
    for header, value in email_headers:
        if header.lower() in ["content-type", "content-transfer-encoding"]:
            if "text/html" in value.lower():
                links.extend(re.findall(r'https?://\S+', value))
    return links

def extract_domain_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def is_hidden_or_shortened_url(url):
    return len(url) < 30  

def check_spf_record(email_headers):
    for header, value in email_headers:
        if header.lower() == "received-spf":
            spf_result = re.search(r'spf=(\S+)', value)
            if spf_result:
                spf_status = spf_result.group(1).lower()
                if spf_status == "pass":
                    return 0  # SPF pass, no score
                elif spf_status == "fail" or spf_status == "softfail":
                    return 25  
                else:
                    return 25 
    
    return 25

def check_dkim(email_headers):
    for header, value in email_headers:
        if header.lower() == "dkim":
            dkim_result = re.search(r'dkim=(\S+)', value)
            if dkim_result:
                dkim_status = dkim_result.group(1).lower()
                if dkim_status == "pass":
                    return 0  
                else:
                    return 15 

    
    return 25

def check_dmarc(email_headers):
    for header, value in email_headers:
        if header.lower() == "authentication-results":
            dmarc_result = re.search(r'dmarc=(\S+)', value)
            if dmarc_result:
                dmarc_status = dmarc_result.group(1).lower()
                if dmarc_status == "pass":
                    return 0  # DMARC pass, no score
                else:
                    return 10  # DMARC fail, moderate score

    
    return 25

def check_content_analysis(email_headers):
    urgent_language_score = 0
    grammar_spelling_score = 0
    attachment_score = 0

    for header, value in email_headers:
        # Check for urgent language
        urgent_words = ["urgent", "immediate", "action required", "important", "deadline"]
        if any(word in value.lower() for word in urgent_words):
            urgent_language_score = 15  # Assigning a weight of 15 for urgent language
            print("Urgent language detected in headers:", header)

        
        if header.lower() == "subject":  # Focus on the subject line
            d = enchant.Dict("en_US")  # Adjust language if needed
            words = value.split()
            for word in words:
                if not d.check(word):
                    grammar_spelling_score += 5  # Assigning a weight of 5 for each error
                    print("Potential spelling error:", word)

        
        if header.lower() == "content-type" and "attachment; filename=" in value.lower():
            filename = re.findall(r'filename="(.*?)"', value.lower())[0]  # Extract filename
            extension = filename.split(".")[-1].lower()
            suspicious_extensions = [".vbs", ".exe", ".bat", ".js"]
            if extension in suspicious_extensions:
                attachment_score = 25  # Assigning a weight of 25 for suspicious attachments
                print(f"Suspicious attachment detected (filename: {filename}, extension: {extension}).")

    
    print("\nContent Analysis Scores:")
    print("- Urgent language score:", urgent_language_score)
    print("- Grammar/spelling errors score:", grammar_spelling_score)
    print("- Suspicious attachment score:", attachment_score)

 
    return urgent_language_score + grammar_spelling_score + attachment_score

def check_unusual_sending_behavior(email_headers):
    sending_time_score = 0
    frequency_score = 0

    
    sending_times = []
    for header, value in email_headers:
        if header.lower() == "date":
            try:
                timestamp = datetime.strptime(value, "%a, %d %b %Y %H:%M:%S %z")
                sending_times.append(timestamp.hour)
            except ValueError:
                print("Error parsing Date header:", value)

    
    if sending_times:
        average_sending_time = sum(sending_times) / len(sending_times)
        if 0 <= average_sending_time <= 6 or 18 <= average_sending_time <= 23:
            sending_time_score = 10  # Assigning a weight of 10 for emails sent during unusual hours
            print("Unusual sending time detected.")

   
    sender_domains = [value.lower() for header, value in email_headers if header.lower() == "from"]
    if sender_domains:
        domain_counter = Counter(sender_domains)
        most_common_domain, most_common_count = domain_counter.most_common(1)[0]
        if most_common_count >= 5:  # Adjust the threshold as needed
            frequency_score = 5  # Assigning a weight of 5 for a sudden spike in emails from one domain
            print(f"Sudden spike in emails from domain: {most_common_domain}")

   
    print("\nUnusual Sending Behavior Scores:")
    print("- Sending time score:", sending_time_score)
    print("- Frequency score:", frequency_score)

    return sending_time_score + frequency_score


def check_reply_to_field(email_headers):
    reply_to_score = 0

   
    sender_email = None
    for header, value in email_headers:
        if header.lower() == "from":
            sender_email = value.lower()

    
    reply_to = None
    for header, value in email_headers:
        if header.lower() == "reply-to":
            reply_to = value.lower()


    if sender_email and reply_to and sender_email != reply_to:
        reply_to_score = 10  
        print("Mismatch in 'reply-to' field detected.")

   
    print("\nReply-To Field Score:")
    print("- Reply-To field score:", reply_to_score)


    return reply_to_score

def check_ip_reputation(email_headers, virustotal_api_key):
    ip_reputation_score = 0

    sender_ip = extract_sender_ip(email_headers)

    if sender_ip:
       
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{sender_ip}",
                                headers={"x-apikey": virustotal_api_key})

        if response.status_code == 200:
            data = response.json()
            reputation = data.get("data", {}).get("attributes", {}).get("reputation")

            if reputation == "malicious":
                ip_reputation_score = 10
                print("Blacklisted IP detected.")
            elif reputation == "suspicious":
                ip_reputation_score = 5
                print("Potentially suspicious IP detected.")

        else:
            print("Error fetching IP reputation from VirusTotal:", response.status_code)

  
    print("\nIP Reputation Score:")
    print("- IP reputation score:", ip_reputation_score)

 
    return ip_reputation_score

def extract_sender_ip(email_headers):
    for header, value in email_headers:
        if header.lower() in ["received-spf", "x-originating-ip"]:
            ip_addresses = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", value)
            if ip_addresses:
                return ip_addresses[0]  

    return None


def main():
    
    with open("C:/Users/nagas/Desktop/Phising/sample-9.eml", "rb") as f:
        email_message = email.message_from_bytes(f.read())

       
        virustotal_api_key = "144e04e3c66a50c35ace51ffb0b626df1f3adb05014f75b861d1966b5ded830c"

       
        total_score, risk_level = calculate_score(email_message.items())

        print(f"Total Score: {total_score}, Risk Level: {risk_level}")


if __name__ == "__main__":
    main()

