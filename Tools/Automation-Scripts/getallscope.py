#!/usr/bin/python

import json
import requests
import argparse
import yaml
from pathlib import Path
import sys
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RequestException
from collections import deque

# Remove the following line if you are no longer using .env
# from dotenv import load_dotenv
# load_dotenv()

def save_config(username, token):
    config_path = Path.home() / '.config' / 'getscope' / 'config.yaml'
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, 'w') as f:
        yaml.dump({'API_USERNAME': username, 'API_TOKEN': token}, f)

def load_config():
    config_path = Path.home() / '.config' / 'getscope' / 'config.yaml'
    if config_path.exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return None

def parse_args():
    parser = argparse.ArgumentParser(description='Retrieve HackerOne program handles and scopes.')
    parser.add_argument('-c', '--config', metavar='username:token', help='Set API username and token in config file')
    parser.add_argument('-b', '--bounty', type=str, choices=['true', 'false'], help='Filter programs by bounty eligibility')
    parser.add_argument('-o', '--output', choices=['txt', 'json'], help='Specify output format: txt or json')
    return parser.parse_args()

args = parse_args()

if args.config:
    try:
        username, token = args.config.split(':', 1)
        save_config(username, token)
        print("Configuration saved successfully.")
    except ValueError:
        print("Invalid format for -c. Use username:token", file=sys.stderr)
        sys.exit(1)
else:
    config = load_config()
    if config:
        username = config.get('API_USERNAME')
        token = config.get('API_TOKEN')
    else:
        print("No configuration found. Use -c to set API credentials.", file=sys.stderr)
        sys.exit(1)

def create_session():
    """Create a session with retry mechanism"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,  # number of retries
        backoff_factor=1,  # wait 1, 2, 4 seconds between retries
        status_forcelist=[429, 500, 502, 503, 504]  # HTTP status codes to retry on
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def make_request(url, auth, headers):
    """Make HTTP request with error handling"""
    session = create_session()
    try:
        response = session.get(url, auth=auth, headers=headers, timeout=30)
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        print(f"[!] Request timed out for {url}", file=sys.stderr)
    except requests.exceptions.ConnectionError:
        print(f"[!] Network error occurred for {url}. Check your internet connection.", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error occurred: {e}", file=sys.stderr)
    return None

def GetPrograms(bounty_filter=None):
    headers = {
        'Accept': 'application/json'
    }
    
    handles = []
    url = 'https://api.hackerone.com/v1/hackers/programs?page[size]=100'
    print("[*] Fetching programs list...")
    
    while url:
        r = make_request(url, auth=(username, token), headers=headers)
        if r is None:
            print("[!] Failed to fetch programs. Retrying...", file=sys.stderr)
            time.sleep(5)
            continue
            
        if r.status_code == 200:
            data = r.json()
            for program in data.get('data', []):
                attributes = program.get('attributes', {})
                handle = attributes.get('handle')
                eligible_for_bounty = attributes.get('eligible_for_bounty', False)
                
                # Check bounty eligibility if filter is applied
                if bounty_filter is not None:
                    bounty_matches = (bounty_filter.lower() == 'true') == eligible_for_bounty
                    if not bounty_matches:
                        continue
                
                if handle:
                    handles.append(handle)
                    
            links = data.get('links', {})
            url = links.get('next')
            time.sleep(1)
        else:
            print(f"[!] Error: {r.status_code}", file=sys.stderr)
            break
    
    return handles

class RateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window  # in seconds
        self.requests = deque()

    def wait_if_needed(self):
        now = time.time()
        
        # Remove old requests outside the time window
        while self.requests and now - self.requests[0] > self.time_window:
            self.requests.popleft()
        
        # If at capacity, wait until oldest request expires
        if len(self.requests) >= self.max_requests:
            sleep_time = self.requests[0] + self.time_window - now
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.requests.popleft()
        
        self.requests.append(now)

# Create rate limiter for 600 requests per minute
rate_limiter = RateLimiter(max_requests=600, time_window=60)

def GetScopes(handle):
    """Fetches and filters target domains for a given program handle."""
    scopes_url = f'https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes'
    headers = {'Accept': 'application/json'}
    domains = []
    
    rate_limiter.wait_if_needed()
    
    r = make_request(scopes_url, auth=(username, token), headers=headers)
    if r is None or r.status_code != 200:
        return []
        
    data = r.json()
    for scope in data.get('data', []):
        attributes = scope.get('attributes', {})
        asset_identifier = attributes.get('asset_identifier', '')
        asset_type = attributes.get('asset_type', '').upper()
        instruction = attributes.get('instruction', '')
        eligible_for_submission = attributes.get('eligible_for_submission', False)
        
        if asset_type in ['WILDCARD', 'URL']:
            domains.append({
                'identifier': asset_identifier,
                'type': asset_type,
                'instruction': instruction,
                'eligible': eligible_for_submission
            })
    
    return domains

try:
    handles = GetPrograms(bounty_filter=args.bounty)
    if not handles:
        sys.exit(1)
    
    # Initialize JSON structure
    output_data = {
        "programs": {},
        "metadata": {
            "total_programs": len(handles),
            "program_type": "bounty" if args.bounty == 'true' else "vdp" if args.bounty == 'false' else "all"
        }
    }
    
    for handle in handles:
        domains = GetScopes(handle)
        if domains:
            # Filter only eligible domains
            urls = [d['identifier'] for d in domains if d['type'] == 'URL' and d['eligible']]
            wildcards = [d['identifier'] for d in domains if d['type'] == 'WILDCARD' and d['eligible']]
            
            if urls or wildcards:
                # Minimal console output
                print(f"\n{"[" + handle +"]\n"}")
                for url in sorted(urls):
                    print(f"{url}")
                for wildcard in sorted(wildcards):
                    print(f"{wildcard}")
                
                # Detailed data for file output
                output_data["programs"][handle] = {
                    "urls": [{
                        "domain": d['identifier'],
                        "instruction": d['instruction'],
                        "eligible": d['eligible']
                    } for d in domains if d['type'] == 'URL'],
                    "wildcards": [{
                        "domain": d['identifier'],
                        "instruction": d['instruction'],
                        "eligible": d['eligible']
                    } for d in domains if d['type'] == 'WILDCARD'],
                    "total_urls": len(urls),
                    "total_wildcards": len(wildcards)
                }
    
    # Save output if format specified
    if args.output == 'json':
        filename = f"scope_{output_data['metadata']['program_type']}_programs.json"
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2)

except KeyboardInterrupt:
    sys.exit(1)