import os
import json
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

STATS_FILE = 'data/stats.json'

# avem nevoie de asta pentru ca pot veni multe request-uri in acelasi timp
# si fisierul nu poate fi folosit de doua procese in acelasi timp
block_stats_file = threading.Lock()

def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading stats: {e}")
    return {
        "total_blocked": 0,
        "blocked_by_company": {},
        "recent_blocked": []
    }

def save_stats(stats):
    os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
    except Exception as e:
        print(f"Error saving stats: {e}")

def get_company_from_domain(domain):
    domain = domain.strip().lower()

    if domain.endswith('.'):
        domain = domain[:-1]

    # fiecare companie este asociata cu anumite keywords (generat cu ai ca eu nu stiam :( )
    mappings = [
        (['google', 'doubleclick', 'googleadservices', 'googlesyndication', 'youtube', 'ytimg', 'adsystem'], 'Google'),
        (['facebook', 'instagram', 'fbsbx', 'fbcdn', 'whatsapp', 'messenger', 'meta'], 'Facebook/Meta'),
        (['microsoft', 'bing', 'skype', 'live', 'office', 'msn', 'visualstudio', 'windowsupdate'], 'Microsoft'),
        (['amazon', 'aws', 'media-amazon', 'assoc-amazon', 'aax-eu'], 'Amazon'),
        (['tiktok', 'byteoversea', 'bytedance', 'musical.ly'], 'TikTok/ByteDance'),
        (['twitter', 't.co', 'twimg', 'x.com'], 'Twitter/X'),
        (['apple', 'icloud', 'mzstatic'], 'Apple'),
        (['yahoo', 'flurry', 'yimg'], 'Yahoo'),
        (['spotify', 'spoti.fi'], 'Spotify'),
        (['netflix', 'nflxso', 'nflxext', 'nflxvideo'], 'Netflix'),
        (['adcolony'], 'AdColony'),
        (['applovin'], 'AppLovin'),
        (['unity3d', 'unity'], 'Unity'),
        (['cloudflare'], 'Cloudflare'),
        (['criteo'], 'Criteo'),
        (['outbrain'], 'Outbrain'),
        (['taboola'], 'Taboola'),
        (['adnxs', 'appnexus'], 'AppNexus'),
        (['pubmatic'], 'PubMatic'),
        (['rubiconproject'], 'Rubicon Project'),
    ]

    for keywords, company in mappings:
        for kw in keywords:
            if kw in domain:
                return company

    # daca cumva nu e o companie listata mai sus
    return "Other"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    with block_stats_file:
        stats = load_stats()
    return jsonify(stats)

@app.route('/block', methods=['POST'])
def block_ad():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"status": "error", "message": "Missing domain in request data"}), 400
    
    domain = data['domain']
    company = get_company_from_domain(domain)
    
    with block_stats_file:
        stats = load_stats()
        stats['total_blocked'] += 1
        stats['blocked_by_company'][company] = stats['blocked_by_company'].get(company, 0) + 1
        
        # adauga in lista de blocate recent
        new_entry = {
            "domain": domain,
            "company": company,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        stats['recent_blocked'].insert(0, new_entry)
        # doar primele 100
        stats['recent_blocked'] = stats['recent_blocked'][:100]
        
        save_stats(stats)
        
    return jsonify({"status": "success"})

@app.route('/api/reset', methods=['POST'])
def reset_stats():
    with block_stats_file:
        stats = {
            "total_blocked": 0,
            "blocked_by_company": {},
            "recent_blocked": []
        }
        save_stats(stats)
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)
