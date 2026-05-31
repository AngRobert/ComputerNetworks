import pandas as pd
from time import sleep
import requests
from random import randint
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1

# these are keywords that the script looks for in the spf records, that indicate that the respective domain uses
# foreign services for hosting
FOREIGN_SPF = {
    # Google
    "include:_spf.google.com",
    "include:_netblocks.google.com",
    "redirect=_spf.google.com",
    # Microsoft / Outlook
    "include:spf.protection.outlook.com",
    "include:spf2.outlook.com",
    # Amazon SES
    "include:amazonses.com",
    # Zoho
    "include:zoho.com",
    "include:zohomail.eu",
    "include:zoho.eu",
    "include:one.zoho.eu",
    # SendGrid
    "include:sendgrid.net",
    # Mailjet
    "include:spf.mailjet.com",
    # Brevo / Sendinblue
    "include:spf.sendinblue.com",
    "include:spf.brevo.com",
    # Mailchimp / Mandrill
    "include:spf.mandrillapp.com",
    "include:spf.mcsv.net",
    # Mailchannels
    "include:relay.mailchannels.net",
    # Yahoo
    "redirect=_spf.mail.yahoo.com",
    # Zendesk
    "include:mail.zendesk.com",
    # Newsman (external)
    "include:newsman.app",
    # US hosters
    "include:websitewelcome.com",
    "include:spf.mysecurecloudhost.com"}
# HAS 3 POSSIBLE OUTPUTS:
# FOREIGN (the ip lookup returns a foreign coutnry code),
# HYBRID (the ip lookup returns RO, but SPF data indicates that foreign services may also be used),
# LOCAL (the ip lookup returns RO, and there is no SPF included emails that indicate any foreign services)
def calculate_provider(spf, country):
    if country is None or country.lower() == "unknown" or country.lower() == "":
        return "unknown", []

    # not romanian country code from the mx ip lookup means definitely foreign
    if country.upper() != "ROMANIA":
        return "foreign", []

    # otherwise, check the SPF
    if not spf:
        return "local", []

    spf = spf.lower().split()
    check = [s for s in spf if s in FOREIGN_SPF]
    if len(check) > 0:
        return "hybrid", check
    else:
        return "local", []

#makes an API call to ipinfo.io in order to get the country and provider
def ip_lookup(ip):
    if not ip:
        return {"country": "unknown", "provider": "unknown"}

    url = f'https://api.ipinfo.io/lite/{ip}?token=5639e9e80fd3db'

    try:
        response = requests.get(url, timeout=5)

        data = response.json()

        country = data.get('country', 'unknown')
        provider = data.get('as_name', 'unknown')

        return {
            "country": country,
            "provider": provider
        }
    except requests.exceptions.RequestException as e:
        print(f"API Error for {ip}: {e}")
        return {"country": "unknown", "provider": "unknown"}

# general dns_query function so that i dont have to rewrite the code every time
def dns_query(domain, qtype):
    packet = (
            IP(dst="8.8.8.8") / # 8.8.8.8 is google's dns resolver
            UDP(sport=randint(10000, 60000), dport=53) / #random sport to avoid a common linux issue
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype, qclass="IN")) #rd = 1 means recursive
    )
    response = sr1(packet, verbose=0, timeout=3)
    if response is None:
        print(f"  [no {qtype} response for {domain}]")
        return None
    dns = response[DNS]
    if dns.rcode != 0: # rcode is the return code
        print(f"  [{qtype} rcode={dns.rcode} for {domain}]")
        return None
    return dns


# load the csv
df = pd.read_csv("query.csv")
# get the domain part of the email column
domains = [x.split('@')[1].strip() for x in df['email']]
# deduplicate the email domains
domains_set = set(domains)

results = {} # dictionary that will hold all results and that will be used for the CSV

# for each domain, send a TXT and MX request and look at what is inside
for d in domains_set:
    # initializing the results dictionary
    results[d] = {
        "domain": d,
        "mx": None,
        "spf": None,
        "ip": None,
        "country": None,
        "provider": None,
        "spf_foreign_keywords": None,
        "classification": "unknown",
    }

    # FIRST SEND THE MX REQUEST
    dns = dns_query(d, 'MX')
    if dns is None:
        continue

    min_prio = 2 ** 16 # the biggest priority number possible is 2^16 - 1
    result_hostname = None

    # if there is at least one answer
    if dns.ancount > 0:
        record = dns.an # accesses that answer

        #record.show()
        while record is not None and hasattr(record, 'type'):
            if record.type == 15:  # MX
                # rdata for MX is in bytes: 2 bytes priority + hostname
                hostname = record.exchange.decode('utf-8').rstrip('.')
                priority = record.preference # lower priority number means higher priority, we will be using the lowest
                #print(f"{d}, priority={priority}, mx={hostname}")
                if priority < min_prio:
                    min_prio = priority
                    result_hostname = hostname

            next_r = record.payload
            record = next_r if hasattr(next_r, 'type') else None

    results[d]['mx'] = result_hostname

    # NOW MAKE THE TXT QUERY
    dns = dns_query(d, 'TXT')

    if dns is not None and dns.ancount > 0:
        record = dns.an # accesses that answer
        #record.show()
        while record is not None and hasattr(record, 'type'):
            if record.type == 16:  # TXT
                data = record.rdata # this is the raw data, it can be an object in bytes or a list of objects in bytes

                if isinstance(data, list):
                    txt = b''.join(data).decode('utf-8', errors='ignore')
                else:
                    txt = data.decode('utf-8', errors='ignore')

                if txt.startswith('v=spf1'): # we have found the spf record and we can exit
                    results[d]['spf'] = txt
                    #print(txt)
                    break

            next_r = record.payload
            record = next_r if hasattr(next_r, 'type') else None

    ip = None

    # next: look up the A record for the domain names and get the IP, also verifying the SPF records
    if results[d]['mx'] is not None:
        dns = dns_query(results[d]['mx'], 'A')

        if dns is not None and dns.ancount > 0:
            record = dns.an
            while record is not None and hasattr(record, 'type'):
                if record.type == 1:
                    ip = record.rdata # the ip of that domain, we can exit after we get it
                    break
                next_r = record.payload
                record = next_r if hasattr(next_r, 'type') else None

    #print(f'ip = {ip}')
    results[d]['ip'] = ip

    # we now have to lookup the ip using the ipinfo.io API
    loc = ip_lookup(ip)
    results[d]["country"] = loc["country"]
    results[d]["provider"] = loc["provider"]

    # finally, get the classification and spf keywords
    results[d]['classification'], results[d]['spf_foreign_keywords'] = calculate_provider(results[d]['spf'], results[d]['country'])

    sleep(0.1)

out_df = pd.DataFrame.from_dict(results, orient="index")[
    ["domain", "mx", "spf", "ip", "country", "provider", "spf_foreign_keywords", "classification"]
]
df['domain'] = df['email'].str.split('@').str[1].str.strip()
df = df.merge(out_df, on='domain', how='left')
df.to_csv("mail_classification.csv", index=False)
